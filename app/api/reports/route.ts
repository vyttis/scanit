import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { generateReport } from '@/lib/report/generator';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * POST /api/reports — Generate a report for a completed scan.
 * Body: { scan_id: string }
 */
export async function POST(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting: max 10 requests/minute per user
  const rateResult = checkRateLimit(`reports:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  // Get user's profile — use service role for superadmin (org_id=NULL breaks RLS)
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

  if (!isSuperadmin && !profile?.org_id) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  let body: { scan_id?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Netinkama užklausa.' }, { status: 400 });
  }

  const scanId = body.scan_id;
  if (!scanId || typeof scanId !== 'string' || !UUID_REGEX.test(scanId)) {
    return NextResponse.json({ error: 'Netinkamas scan_id formatas.' }, { status: 400 });
  }

  // Verify scan belongs to user's organization (superadmin can access all)
  const scanClient = isSuperadmin ? createServiceRoleClient() : supabase;
  const { data: scan } = await scanClient
    .from('scans')
    .select('id, org_id, status')
    .eq('id', scanId)
    .single();

  if (!scan) {
    return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
  }

  if (scan.status !== 'completed') {
    return NextResponse.json(
      { error: 'Ataskaita gali būti generuojama tik baigtiems skenavimams.' },
      { status: 400 },
    );
  }

  // Check if report already exists for this scan
  const serviceClient = createServiceRoleClient();
  const { data: existingReport } = await serviceClient
    .from('reports')
    .select('id, pdf_path')
    .eq('scan_id', scanId)
    .single();

  if (existingReport?.pdf_path) {
    // Return existing report's signed URL
    const { data: signedUrlData } = await serviceClient.storage
      .from('reports')
      .createSignedUrl(existingReport.pdf_path, 3600);

    if (signedUrlData?.signedUrl) {
      // Audit log: report downloaded
      const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
        request.headers.get('x-real-ip') || 'unknown';

      await serviceClient.from('audit_log').insert({
        org_id: scan.org_id,
        user_id: user.id,
        action: 'report_downloaded',
        details: { report_id: existingReport.id, scan_id: scanId },
        ip_address: ip,
      });

      return NextResponse.json({
        report_id: existingReport.id,
        signed_url: signedUrlData.signedUrl,
        message: 'Ataskaita jau sugeneruota.',
      });
    }
  }

  try {
    const result = await generateReport(scanId);

    // Audit log: report generated
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      request.headers.get('x-real-ip') || 'unknown';

    await serviceClient.from('audit_log').insert({
      org_id: scan.org_id,
      user_id: user.id,
      action: 'report_generated',
      details: { report_id: result.reportId, scan_id: scanId, risk_score: result.riskScore },
      ip_address: ip,
    });

    return NextResponse.json({
      report_id: result.reportId,
      signed_url: result.signedUrl,
      risk_score: result.riskScore,
      message: 'Ataskaita sėkmingai sugeneruota.',
    });
  } catch (err) {
    console.error('Report generation failed:', err);
    return NextResponse.json(
      { error: 'Klaida generuojant ataskaitą. Bandykite dar kartą.' },
      { status: 500 },
    );
  }
}

/**
 * GET /api/reports?scan_id=xxx — Get signed URL for an existing report.
 */
export async function GET(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting
  const rateResultGet = checkRateLimit(`reports-get:${user.id}`);
  if (!rateResultGet.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę.' },
      { status: 429, headers: rateLimitHeaders(rateResultGet) },
    );
  }

  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get('scan_id');

  if (!scanId || !UUID_REGEX.test(scanId)) {
    return NextResponse.json({ error: 'Netinkamas scan_id formatas.' }, { status: 400 });
  }

  // Check user role — superadmin needs service role to bypass RLS
  const getProfileClient = createServiceRoleClient();
  const { data: getProfile } = await getProfileClient
    .from('profiles')
    .select('org_id, role, status')
    .eq('id', user.id)
    .single();

  if (getProfile?.status === 'suspended') {
    return NextResponse.json({ error: 'Jūsų paskyra sustabdyta.' }, { status: 403 });
  }

  const isGetSuperadmin = getProfile?.role === 'superadmin';
  const reportClient = isGetSuperadmin ? getProfileClient : supabase;

  const { data: report } = await reportClient
    .from('reports')
    .select('id, scan_id, org_id, pdf_path, risk_score, critical_count, high_count, medium_count, low_count, created_at')
    .eq('scan_id', scanId)
    .single();

  if (!report || !report.pdf_path) {
    return NextResponse.json({ error: 'Ataskaita nerasta.' }, { status: 404 });
  }

  const serviceClient = createServiceRoleClient();
  const { data: signedUrlData, error: signedUrlError } = await serviceClient.storage
    .from('reports')
    .createSignedUrl(report.pdf_path, 3600);

  if (signedUrlError || !signedUrlData?.signedUrl) {
    console.error('Signed URL error for report', report.id, ':', signedUrlError);
    return NextResponse.json({ error: 'Klaida generuojant atsisiuntimo nuorodą.' }, { status: 500 });
  }

  // Audit log: report downloaded
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';

  await serviceClient.from('audit_log').insert({
    org_id: report.org_id,
    user_id: user.id,
    action: 'report_downloaded',
    details: { report_id: report.id, scan_id: scanId },
    ip_address: ip,
  });

  return NextResponse.json({
    report_id: report.id,
    signed_url: signedUrlData.signedUrl,
    risk_score: report.risk_score,
    critical_count: report.critical_count,
    high_count: report.high_count,
    medium_count: report.medium_count,
    low_count: report.low_count,
    created_at: report.created_at,
  });
}
