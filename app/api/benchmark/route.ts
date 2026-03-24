import { NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

/**
 * GET /api/benchmark
 * Returns anonymous sector benchmark data for the user's organization.
 * Only shows benchmarks when ≥5 organizations exist in the sector (privacy).
 */
export async function GET() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neprisijungęs.' }, { status: 401 });
  }

  const rl = checkRateLimit(user.id);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų.' },
      { status: 429, headers: rateLimitHeaders(rl) },
    );
  }

  const serviceClient = createServiceRoleClient();

  // Get user's org
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id')
    .eq('id', user.id)
    .single();

  if (!profile?.org_id) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  const { data: org } = await serviceClient
    .from('organizations')
    .select('id, sector')
    .eq('id', profile.org_id)
    .single();

  if (!org?.sector) {
    return NextResponse.json({
      available: false,
      reason: 'no_sector',
    }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  // Get user's latest risk score
  const { data: userReport } = await serviceClient
    .from('reports')
    .select('risk_score')
    .eq('org_id', org.id)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!userReport?.risk_score && userReport?.risk_score !== 0) {
    return NextResponse.json({
      available: false,
      reason: 'no_scan',
    }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  // Count organizations in same sector with reports
  const { data: sectorOrgs } = await serviceClient
    .from('organizations')
    .select('id')
    .eq('sector', org.sector);

  const sectorOrgIds = (sectorOrgs ?? []).map((o) => o.id);

  if (sectorOrgIds.length < 5) {
    return NextResponse.json({
      available: false,
      reason: 'insufficient_data',
      sector_count: sectorOrgIds.length,
      minimum_required: 5,
    }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  // Get latest risk scores for all sector orgs
  const { data: allReports } = await serviceClient
    .from('reports')
    .select('org_id, risk_score, created_at')
    .in('org_id', sectorOrgIds)
    .order('created_at', { ascending: false })
    .limit(10000);

  // Get latest report per org
  const latestScores = new Map<string, number>();
  for (const r of allReports ?? []) {
    if (r.risk_score !== null && !latestScores.has(r.org_id)) {
      latestScores.set(r.org_id, r.risk_score);
    }
  }

  const scores = Array.from(latestScores.values());
  if (scores.length < 5) {
    return NextResponse.json({
      available: false,
      reason: 'insufficient_data',
    }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  // Calculate percentile (lower risk score = better)
  const userScore = userReport.risk_score;
  const betterThan = scores.filter((s) => s > userScore).length;
  const percentile = Math.round((betterThan / scores.length) * 100);

  const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);

  return NextResponse.json({
    available: true,
    user_score: userScore,
    sector_avg: avgScore,
    percentile,
    sector_count: scores.length,
    sector: org.sector,
  }, { status: 200, headers: rateLimitHeaders(rl) });
}
