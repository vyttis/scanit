import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { waitUntil } from '@vercel/functions';
import { runAllScanners, checkScannerEnvVars } from '@/lib/scanners';
import type { ScannerOptions } from '@/lib/scanners';
import { generateReport } from '@/lib/report/generator';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import { sendEmail } from '@/lib/email/send';
import { scanStartedHtml } from '@/lib/email/templates/scan-started';
import { scanCompletedHtml } from '@/lib/email/templates/scan-completed';
import { criticalFindingsHtml } from '@/lib/email/templates/critical-findings';
import { isValidCidr } from '@/lib/validations';

export const maxDuration = 120;

/**
 * Sanitize scanner error messages before storing or returning to frontend.
 * Strips references to API key env var names and raw API error details.
 */
function sanitizeScannerError(error: string): string {
  // Replace env var name references like "SHODAN_API_KEY not configured"
  if (/[A-Z_]+_API_KEY/i.test(error) || /not configured/i.test(error)) {
    return 'Skenavimo modulis nesukonfigūruotas.';
  }
  // Strip raw HTTP error bodies or stack traces
  if (error.length > 200) {
    return error.slice(0, 200);
  }
  return error;
}

export async function POST(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting: max 10 requests/minute per user
  const rateResult = checkRateLimit(`scan:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  // Get user's profile — use service role to avoid RLS issues for superadmin (org_id=NULL)
  const profileClient = createServiceRoleClient();
  const { data: profile } = await profileClient
    .from('profiles')
    .select('org_id, role, status')
    .eq('id', user.id)
    .single();

  if (profile?.status === 'suspended') {
    return NextResponse.json({ error: 'Jūsų paskyra sustabdyta.' }, { status: 403 });
  }

  const isSuperadmin = profile?.role === 'superadmin';

  // Only admins and superadmins can trigger scans
  if (profile?.role !== 'admin' && !isSuperadmin) {
    return NextResponse.json({ error: 'Tik administratoriai gali inicijuoti skenavimą.' }, { status: 403 });
  }

  // Parse request body (may contain org_id for superadmin, plus scan scope params)
  const body = await request.clone().json().catch(() => ({}));

  // Superadmin can scan any org by passing org_id in the request body
  let targetOrgId = profile?.org_id;
  if (isSuperadmin) {
    targetOrgId = body.org_id || profile?.org_id;
  }

  if (!targetOrgId) {
    return NextResponse.json({ error: 'Organizacija nerasta. Nurodykite org_id.' }, { status: 404 });
  }

  const serviceClient = createServiceRoleClient();

  // Get organization and verify domain ownership
  const { data: org } = await serviceClient
    .from('organizations')
    .select('*')
    .eq('id', targetOrgId)
    .single();

  if (!org) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  // SECURITY: Domain must be verified before scanning (superadmin can bypass for testing)
  if (!org.verified && !isSuperadmin) {
    return NextResponse.json(
      { error: 'Domenas nepatvirtintas. Prieš skenavimą turite patvirtinti domeno nuosavybę.' },
      { status: 403 },
    );
  }

  // --- Plan-based scan parameter enforcement (server-side, never trust client) ---
  // Plan lives on organizations table, not profiles
  const userPlan = org?.plan || 'basic';
  const requestedIpRanges: string[] = Array.isArray(body.ip_ranges) ? body.ip_ranges : [];
  const requestedSubdomains: string[] = Array.isArray(body.subdomains) ? body.subdomains : [];
  const requestedEmails: string[] = Array.isArray(body.emails) ? body.emails : [];

  if (requestedIpRanges.length > 0 && userPlan !== 'professional' && !isSuperadmin) {
    return NextResponse.json(
      { error: 'IP adresų skenavimas prieinamas tik Profesionalaus plano vartotojams.' },
      { status: 403 },
    );
  }
  if (requestedSubdomains.length > 0 && userPlan !== 'professional' && !isSuperadmin) {
    return NextResponse.json(
      { error: 'Subdomainų skenavimas prieinamas tik Profesionalaus plano vartotojams.' },
      { status: 403 },
    );
  }
  if (requestedEmails.length > 0 && userPlan !== 'professional' && !isSuperadmin) {
    return NextResponse.json(
      { error: 'El. pašto skenavimas prieinamas tik Profesionalaus plano vartotojams.' },
      { status: 403 },
    );
  }

  // Validate IP ranges (CIDR format)
  for (const cidr of requestedIpRanges) {
    if (typeof cidr !== 'string' || !isValidCidr(cidr)) {
      return NextResponse.json(
        { error: `Netinkamas CIDR formatas: ${String(cidr).slice(0, 50)}` },
        { status: 400 },
      );
    }
  }

  // Validate subdomains (basic domain format check)
  const subdomainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  for (const sub of requestedSubdomains) {
    if (typeof sub !== 'string' || !subdomainRegex.test(sub)) {
      return NextResponse.json(
        { error: `Netinkamas subdomeno formatas: ${String(sub).slice(0, 50)}` },
        { status: 400 },
      );
    }
  }

  // Validate emails (basic format check)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  for (const email of requestedEmails) {
    if (typeof email !== 'string' || !emailRegex.test(email)) {
      return NextResponse.json(
        { error: `Netinkamas el. pašto formatas: ${String(email).slice(0, 50)}` },
        { status: 400 },
      );
    }
  }

  // Build scanner options (emails are in-memory only, never stored in DB)
  const scannerOptions: ScannerOptions = {};
  if (requestedIpRanges.length > 0) scannerOptions.ipRanges = requestedIpRanges;
  if (requestedSubdomains.length > 0) scannerOptions.subdomains = requestedSubdomains;
  if (requestedEmails.length > 0) scannerOptions.emails = requestedEmails;

  // Check for duplicate concurrent scans
  const { data: activeScan } = await serviceClient
    .from('scans')
    .select('id, status')
    .eq('org_id', org.id)
    .in('status', ['queued', 'running'])
    .single();

  if (activeScan) {
    return NextResponse.json(
      { error: 'Skenavimas jau vykdomas. Palaukite, kol dabartinis skenavimas bus baigtas.' },
      { status: 409 },
    );
  }

  // Get IP from request headers for audit log
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';

  // Determine scan type based on inputs
  const hasExtraInputs = requestedIpRanges.length > 0 || requestedSubdomains.length > 0 || requestedEmails.length > 0;
  const scanType = hasExtraInputs ? 'deep' : 'light';

  // Create scan record
  const { data: scan, error: scanError } = await serviceClient
    .from('scans')
    .insert({
      org_id: org.id,
      scan_type: scanType,
      status: 'queued',
      triggered_by: user.id,
    })
    .select()
    .single();

  if (scanError || !scan) {
    return NextResponse.json({ error: 'Klaida kuriant skenavimo įrašą.' }, { status: 500 });
  }

  // Audit log: scan triggered
  await serviceClient.from('audit_log').insert({
    org_id: org.id,
    user_id: user.id,
    action: 'scan_triggered',
    details: {
      scan_id: scan.id,
      domain: org.domain,
      scan_type: scanType,
      is_superadmin_scan: isSuperadmin,
      target_org_id: targetOrgId,
      scope: {
        ip_range_count: requestedIpRanges.length,
        subdomain_count: requestedSubdomains.length,
        email_count: requestedEmails.length,
      },
    },
    ip_address: ip,
  });

  // Get user profile info for email notifications
  const { data: userProfile } = await serviceClient
    .from('profiles')
    .select('first_name')
    .eq('id', user.id)
    .single();

  // Send scan-started email (fire-and-forget)
  const scanDate = new Date().toLocaleString('lt-LT', { timeZone: 'Europe/Vilnius' });
  sendEmail({
    to: org.contact_email,
    subject: `scanit.lt — Skenavimas pradėtas (${org.domain})`,
    html: scanStartedHtml({
      firstName: userProfile?.first_name || 'Vartotojau',
      organizationName: org.name,
      domain: org.domain,
      scanDate,
    }),
  }).catch((err) => console.error('Scan started email error:', err));

  // Start scan in background — waitUntil keeps the function alive after response is sent
  waitUntil(
    executeScan(serviceClient, scan.id, org.id, org.domain, org.name, org.contact_email, userProfile?.first_name || 'Vartotojau', scannerOptions)
  );

  return NextResponse.json({
    scan_id: scan.id,
    status: 'queued',
    message: 'Skenavimas pradėtas. Stebėkite būseną valdymo skydelyje.',
  });
}

/**
 * Execute the scan — runs all 8 modules in parallel, stores findings.
 * This runs in the background after the HTTP response is sent.
 */
async function executeScan(
  serviceClient: ReturnType<typeof createServiceRoleClient>,
  scanId: string,
  orgId: string,
  domain: string,
  orgName: string,
  contactEmail: string,
  firstName: string,
  scannerOptions?: ScannerOptions,
) {
  // Update scan status to running
  await serviceClient
    .from('scans')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', scanId);

  try {
    // Run all 8 scanners in parallel (pass optional scope params for professional plan)
    const results = await runAllScanners(domain, scannerOptions);

    // Track scanner success/failure for visibility
    const failedScanners = results.filter((r) => !r.success);
    const succeededScanners = results.filter((r) => r.success);
    // Sanitize error messages: strip any references to API keys or env var names
    const scannerErrors = failedScanners.map((r) => ({
      module: r.module,
      error: sanitizeScannerError(r.error ?? 'Unknown error'),
    }));

    if (failedScanners.length > 0) {
      console.error(`Scan ${scanId}: ${failedScanners.length} scanner(s) failed:`, scannerErrors);
    }
    console.log(`Scan ${scanId}: ${succeededScanners.length}/8 scanners succeeded, ${failedScanners.length}/8 failed`);

    // Log env var diagnostics to server console only (never expose to frontend)
    const envCheck = checkScannerEnvVars();
    console.log(`Scan ${scanId} env var check:`, envCheck);

    // Store only scanner errors (no env diagnostics) in scan record for UI
    await serviceClient
      .from('scans')
      .update({
        scanner_errors: scannerErrors.length > 0 ? scannerErrors : [],
      })
      .eq('id', scanId);

    // Collect all findings from all scanners
    const allFindings = results.flatMap((result) =>
      result.findings.map((finding) => ({
        scan_id: scanId,
        org_id: orgId,
        module: finding.module,
        severity: finding.severity,
        title_lt: finding.title_lt,
        description_lt: finding.description_lt,
        recommendation_lt: finding.recommendation_lt,
        nis2_article: finding.nis2_article,
        evidence: finding.evidence,
      })),
    );

    // Store all findings in one batch — fail the scan if DB insert fails
    if (allFindings.length > 0) {
      const { error: findingsError } = await serviceClient
        .from('findings')
        .insert(allFindings);

      if (findingsError) {
        console.error('Error storing findings:', findingsError);
        throw new Error(`Failed to store findings: ${findingsError.message}`);
      }
    }

    // If ALL scanners failed and there are zero findings, mark as failed
    if (succeededScanners.length === 0) {
      throw new Error(`All 8 scanners failed. Errors: ${scannerErrors.map(e => `${e.module}: ${e.error}`).join('; ')}`);
    }

    // Mark scan as completed
    const { error: statusError } = await serviceClient
      .from('scans')
      .update({ status: 'completed', completed_at: new Date().toISOString() })
      .eq('id', scanId);

    if (statusError) {
      throw new Error(`Failed to update scan ${scanId} status to completed: ${statusError.message}`);
    }

    // Auto-generate report after successful scan
    let riskScore = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    try {
      const reportResult = await generateReport(scanId);
      riskScore = reportResult.riskScore;
    } catch (reportErr) {
      // Report generation failure: log but don't fail scan (findings are still stored)
      console.error(`Report generation failed for scan ${scanId}:`, reportErr);
      // Store the error in scanner_errors for visibility
      await serviceClient
        .from('scans')
        .update({
          scanner_errors: [
            ...scannerErrors,
            { module: 'report_generation', error: sanitizeScannerError(reportErr instanceof Error ? reportErr.message : 'Unknown error') },
          ],
        })
        .eq('id', scanId);
    }

    // Count findings for email
    criticalCount = allFindings.filter(f => f.severity === 'critical').length;
    highCount = allFindings.filter(f => f.severity === 'high').length;
    mediumCount = allFindings.filter(f => f.severity === 'medium').length;
    lowCount = allFindings.filter(f => f.severity === 'low').length;

    // Send scan-completed email
    const completedDate = new Date().toLocaleString('lt-LT', { timeZone: 'Europe/Vilnius' });
    sendEmail({
      to: contactEmail,
      subject: `scanit.lt — Skenavimas baigtas (${domain})`,
      html: scanCompletedHtml({
        firstName,
        organizationName: orgName,
        domain,
        scanDate: completedDate,
        riskScore,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      }),
    }).catch((err) => console.error('Scan completed email error:', err));

    // Send critical findings alert if any
    if (criticalCount > 0) {
      const criticalFindings = allFindings
        .filter(f => f.severity === 'critical')
        .map(f => ({ title: f.title_lt, module: f.module }));

      sendEmail({
        to: contactEmail,
        subject: `scanit.lt — Rasta ${criticalCount} kritinių pažeidžiamumų (${domain})`,
        html: criticalFindingsHtml({
          firstName,
          organizationName: orgName,
          domain,
          criticalCount,
          findings: criticalFindings,
        }),
      }).catch((err) => console.error('Critical findings email error:', err));
    }
  } catch (err) {
    // Mark scan as failed — never expose raw error to frontend
    console.error(`Scan ${scanId} failed:`, err);
    await serviceClient
      .from('scans')
      .update({ status: 'failed', completed_at: new Date().toISOString() })
      .eq('id', scanId);
  }
}

// GET endpoint to check scan status
export async function GET(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting
  const rateResult = checkRateLimit(`scan-status:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get('id');

  if (!scanId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scanId)) {
    return NextResponse.json({ error: 'Netinkamas skenavimo ID formatas.' }, { status: 400 });
  }

  // Check user role — superadmin needs service role to bypass RLS (org_id=NULL)
  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  // Superadmin uses service role (can see all scans); regular users use RLS
  const queryClient = isSuperadmin ? serviceClient : supabase;
  const { data: scan } = await queryClient
    .from('scans')
    .select('id, status, started_at, completed_at, created_at, scanner_errors')
    .eq('id', scanId)
    .single();

  if (!scan) {
    return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
  }

  // For non-superadmin, verify they can only see their own org's scans
  // This MUST happen before any write operations to prevent cross-org updates
  if (!isSuperadmin && profile?.org_id) {
    const { data: scanOrg } = await supabase
      .from('scans')
      .select('id')
      .eq('id', scanId)
      .eq('org_id', profile.org_id)
      .single();

    if (!scanOrg) {
      return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
    }
  }

  // Stale scan detection: if running/queued for more than 10 minutes, auto-mark as failed
  // Only after ownership is verified above
  const STALE_SCAN_TIMEOUT_MS = 10 * 60 * 1000;
  if (
    (scan.status === 'running' || scan.status === 'queued') &&
    (scan.started_at || scan.created_at) &&
    Date.now() - new Date(scan.started_at || scan.created_at).getTime() > STALE_SCAN_TIMEOUT_MS
  ) {
    const timeoutError = [{ module: 'system', error: 'Skenavimas buvo nutrauktas dėl laiko limito.' }];
    await serviceClient
      .from('scans')
      .update({
        status: 'failed',
        completed_at: new Date().toISOString(),
        scanner_errors: timeoutError,
      })
      .eq('id', scanId);
    scan.status = 'failed';
    scan.completed_at = new Date().toISOString();
    scan.scanner_errors = timeoutError;
  }

  // Sanitize scanner_errors before returning to frontend
  if (scan.scanner_errors && Array.isArray(scan.scanner_errors)) {
    scan.scanner_errors = scan.scanner_errors.map((e: { module: string; error: string }) => ({
      module: e.module,
      error: sanitizeScannerError(e.error),
    }));
  }

  return NextResponse.json(scan);
}
