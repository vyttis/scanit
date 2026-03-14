import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

export const maxDuration = 30;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * GET /api/reports/download?scan_id=xxx
 *
 * Proxies the PDF from Supabase Storage through our domain so the
 * user sees platform.scanit.lt in the browser URL, not supabase.co.
 * Sets correct Content-Type and Content-Disposition headers.
 */
export async function GET(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  const rateResult = checkRateLimit(`reports-download:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get('scan_id');

  if (!scanId || !UUID_REGEX.test(scanId)) {
    return NextResponse.json({ error: 'Netinkamas scan_id formatas.' }, { status: 400 });
  }

  // Check user role — superadmin needs service role to bypass RLS
  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role, status')
    .eq('id', user.id)
    .single();

  if (profile?.status === 'suspended') {
    return NextResponse.json({ error: 'Jūsų paskyra sustabdyta.' }, { status: 403 });
  }

  const isSuperadmin = profile?.role === 'superadmin';
  const reportClient = isSuperadmin ? serviceClient : supabase;

  // Fetch report record (RLS enforced for non-superadmin)
  const { data: report } = await reportClient
    .from('reports')
    .select('id, scan_id, org_id, pdf_path')
    .eq('scan_id', scanId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!report || !report.pdf_path) {
    return NextResponse.json({ error: 'Ataskaita nerasta.' }, { status: 404 });
  }

  // Fetch the organization domain for the filename
  const { data: org } = await serviceClient
    .from('organizations')
    .select('domain')
    .eq('id', report.org_id)
    .single();

  // Download the file from Supabase Storage
  const { data: fileData, error: downloadError } = await serviceClient.storage
    .from('reports')
    .download(report.pdf_path);

  if (downloadError || !fileData) {
    console.error('Report download error:', downloadError);
    return NextResponse.json({ error: 'Klaida atsisiunčiant ataskaitą.' }, { status: 500 });
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

  // Build filename
  const domain = org?.domain ?? 'domenas';
  const dateStr = new Date().toISOString().split('T')[0];
  const filename = `ataskaita-${domain}-${dateStr}.pdf`;

  // Determine content type based on file extension
  const isPdf = report.pdf_path.endsWith('.pdf');
  const contentType = isPdf ? 'application/pdf' : 'text/html; charset=utf-8';
  const disposition = isPdf ? `inline; filename="${filename}"` : 'inline';

  const arrayBuffer = await fileData.arrayBuffer();

  return new NextResponse(Buffer.from(arrayBuffer), {
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': disposition,
      'Cache-Control': 'private, no-cache, no-store',
    },
  });
}
