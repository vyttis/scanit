import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { runAllScanners } from '@/lib/scanners';
import { generateReport } from '@/lib/report/generator';

export async function POST(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Get user's profile and org
  const { data: profile } = await supabase
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  if (!profile?.org_id) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  // Only admins can trigger scans
  if (profile.role !== 'admin') {
    return NextResponse.json({ error: 'Tik administratoriai gali inicijuoti skenavimą.' }, { status: 403 });
  }

  const serviceClient = createServiceRoleClient();

  // Get organization and verify domain ownership
  const { data: org } = await serviceClient
    .from('organizations')
    .select('*')
    .eq('id', profile.org_id)
    .single();

  if (!org) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  // SECURITY: Domain must be verified before scanning
  if (!org.verified) {
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

  // Start scan in background (don't await in response)
  executeScan(serviceClient, scan.id, org.id, org.domain).catch((err) => {
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
) {
  // Update scan status to running
  await serviceClient
    .from('scans')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', scanId);

  try {
    // Run all 8 scanners in parallel
    const results = await runAllScanners(domain);

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

    // Store all findings in one batch
    if (allFindings.length > 0) {
      const { error: findingsError } = await serviceClient
        .from('findings')
        .insert(allFindings);

      if (findingsError) {
        console.error('Error storing findings:', findingsError);
      }
    }

    // Log failed scanners (for monitoring, not exposed to frontend)
    const failedScanners = results.filter((r) => !r.success);
    if (failedScanners.length > 0) {
      console.error('Failed scanners:', failedScanners.map((r) => ({
        module: r.module,
        error: r.error,
      })));
    }

    // Mark scan as completed
    await serviceClient
      .from('scans')
      .update({ status: 'completed', completed_at: new Date().toISOString() })
      .eq('id', scanId);

    // Auto-generate report after successful scan
    try {
      await generateReport(scanId);
      console.log(`Report generated for scan ${scanId}`);
    } catch (reportErr) {
      // Report generation failure should not mark the scan as failed
      console.error(`Report generation failed for scan ${scanId}:`, reportErr);
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

  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get('id');

  if (!scanId) {
    return NextResponse.json({ error: 'Skenavimo ID nepateiktas.' }, { status: 400 });
  }

  // RLS ensures user can only see their own org's scans
  const { data: scan } = await supabase
    .from('scans')
    .select('id, status, started_at, completed_at, created_at')
    .eq('id', scanId)
    .single();

  if (!scan) {
    return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
  }

  return NextResponse.json(scan);
}
