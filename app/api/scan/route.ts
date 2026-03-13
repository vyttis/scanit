import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { runAllScanners } from '@/lib/scanners';
import { generateReport } from '@/lib/report/generator';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import { sendEmail } from '@/lib/email/send';
import { scanStartedHtml } from '@/lib/email/templates/scan-started';
import { scanCompletedHtml } from '@/lib/email/templates/scan-completed';
import { criticalFindingsHtml } from '@/lib/email/templates/critical-findings';

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
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  // Only admins and superadmins can trigger scans
  if (profile?.role !== 'admin' && !isSuperadmin) {
    return NextResponse.json({ error: 'Tik administratoriai gali inicijuoti skenavimą.' }, { status: 403 });
  }

  // Superadmin can scan any org by passing org_id in the request body
  let targetOrgId = profile?.org_id;
  if (isSuperadmin) {
    const body = await request.clone().json().catch(() => ({}));
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

  // Create scan record
  const { data: scan, error: scanError } = await serviceClient
    .from('scans')
    .insert({
      org_id: org.id,
      scan_type: 'light',
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
    details: { scan_id: scan.id, domain: org.domain, scan_type: 'light' },
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

  // Start scan in background (don't await in response)
  executeScan(serviceClient, scan.id, org.id, org.domain, org.name, org.contact_email, userProfile?.first_name || 'Vartotojau').catch((err) => {
    console.error(`Scan ${scan.id} background execution error:`, err);
  });

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
) {
  // Update scan status to running
  await serviceClient
    .from('scans')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', scanId);

  try {
    // Run all 8 scanners in parallel
    const results = await runAllScanners(domain);

    // Track scanner success/failure for visibility
    const failedScanners = results.filter((r) => !r.success);
    const succeededScanners = results.filter((r) => r.success);
    const scannerErrors = failedScanners.map((r) => ({
      module: r.module,
      error: r.error ?? 'Unknown error',
    }));

    if (failedScanners.length > 0) {
      console.error(`Scan ${scanId}: ${failedScanners.length} scanner(s) failed:`, scannerErrors);
    }
    console.log(`Scan ${scanId}: ${succeededScanners.length}/8 scanners succeeded, ${failedScanners.length}/8 failed`);

    // Store scanner errors in scan record for UI visibility
    await serviceClient
      .from('scans')
      .update({
        scanner_errors: scannerErrors.length > 0 ? scannerErrors : null,
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
      console.error(`Failed to update scan ${scanId} status to completed:`, statusError);
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
            { module: 'report_generation', error: reportErr instanceof Error ? reportErr.message : 'Unknown error' },
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

  return NextResponse.json(scan);
}
