import { createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

/**
 * GET /api/public-scan/results?id=<uuid>
 * Returns public scan results (findings with titles + severities only).
 */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return NextResponse.json({ error: 'Netinkamas ID formatas.' }, { status: 400 });
  }

  const serviceClient = createServiceRoleClient();
  const { data: scan } = await serviceClient
    .from('public_scans')
    .select('id, domain, status, results, risk_score, critical_count, high_count, medium_count, low_count, created_at')
    .eq('id', id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
  }

  if (scan.status !== 'completed') {
    return NextResponse.json({ error: 'Skenavimas dar nebaigtas.' }, { status: 400 });
  }

  return NextResponse.json({
    id: scan.id,
    domain: scan.domain,
    status: scan.status,
    results: scan.results,
    risk_score: scan.risk_score,
    critical_count: scan.critical_count,
    high_count: scan.high_count,
    medium_count: scan.medium_count,
    low_count: scan.low_count,
    created_at: scan.created_at,
  });
}
