import { NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import type { Finding } from '@/types/database';

/**
 * GET /api/findings/export?scan_id=...&format=csv|json
 * Export findings for a given scan in CSV or JSON format.
 */
export async function GET(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neprisijungęs.' }, { status: 401 });
  }

  // Rate limit
  const rl = checkRateLimit(user.id);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rl) },
    );
  }

  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get('scan_id');
  const format = searchParams.get('format') || 'csv';

  if (!scanId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scanId)) {
    return NextResponse.json({ error: 'Trūksta arba neteisingas scan_id.' }, { status: 400 });
  }

  if (format !== 'csv' && format !== 'json') {
    return NextResponse.json({ error: 'Formatas turi būti csv arba json.' }, { status: 400 });
  }

  // Check access: user must own the scan's organization
  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  const { data: scan } = await (isSuperadmin ? serviceClient : supabase)
    .from('scans')
    .select('id, org_id')
    .eq('id', scanId)
    .single();

  if (!scan) {
    return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
  }

  if (!isSuperadmin && scan.org_id !== profile?.org_id) {
    return NextResponse.json({ error: 'Prieiga uždrausta.' }, { status: 403 });
  }

  // Fetch findings
  const { data: findings } = await (isSuperadmin ? serviceClient : supabase)
    .from('findings')
    .select('*')
    .eq('scan_id', scanId)
    .order('created_at', { ascending: true });

  const allFindings: Finding[] = (findings ?? []) as Finding[];

  // Audit log the export
  await serviceClient.from('audit_log').insert({
    org_id: scan.org_id,
    user_id: user.id,
    action: 'findings_exported',
    details: { scan_id: scanId, format, finding_count: allFindings.length },
    ip_address: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || null,
  });

  if (format === 'json') {
    const exportData = allFindings.map((f) => ({
      id: f.id,
      module: f.module,
      severity: f.severity,
      title: f.title_lt,
      description: f.description_lt,
      recommendation: f.recommendation_lt,
      kis_article: f.nis2_article,
      evidence: f.evidence,
      created_at: f.created_at,
    }));

    return new NextResponse(JSON.stringify(exportData, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="trukumai-${scanId.slice(0, 8)}.json"`,
        ...rateLimitHeaders(rl),
      },
    });
  }

  // CSV format
  const csvHeader = 'Sunkumas;Modulis;Pavadinimas;Aprašymas;Rekomendacijos;KSĮ straipsnis;Data';
  const csvRows = allFindings.map((f) => {
    const escapeCsv = (s: string) => `"${s.replace(/"/g, '""').replace(/\n/g, ' ')}"`;
    return [
      escapeCsv(f.severity),
      escapeCsv(f.module),
      escapeCsv(f.title_lt),
      escapeCsv(f.description_lt),
      escapeCsv(f.recommendation_lt),
      escapeCsv(f.nis2_article || ''),
      escapeCsv(f.created_at),
    ].join(';');
  });

  const csvContent = '\uFEFF' + [csvHeader, ...csvRows].join('\n'); // BOM for Excel Lithuanian support

  return new NextResponse(csvContent, {
    status: 200,
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="trukumai-${scanId.slice(0, 8)}.csv"`,
      ...rateLimitHeaders(rl),
    },
  });
}
