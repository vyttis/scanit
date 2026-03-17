import { NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import type { FindingStatusType } from '@/types/database';

const VALID_STATUSES: FindingStatusType[] = ['open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'];

/**
 * PATCH /api/findings/status
 * Update the status of a finding (remediation tracking).
 * Body: { finding_id, status, note? }
 */
export async function PATCH(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neprisijungęs.' }, { status: 401 });
  }

  const rl = checkRateLimit(user.id);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rl) },
    );
  }

  const body = await request.json().catch(() => null);
  if (!body?.finding_id || !body?.status) {
    return NextResponse.json({ error: 'Trūksta finding_id arba status.' }, { status: 400 });
  }

  const { finding_id, status, note } = body as {
    finding_id: string;
    status: FindingStatusType;
    note?: string;
  };

  // Validate UUID
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(finding_id)) {
    return NextResponse.json({ error: 'Neteisingas finding_id formatas.' }, { status: 400 });
  }

  // Validate status
  if (!VALID_STATUSES.includes(status)) {
    return NextResponse.json({ error: `Neteisingas statusas. Galimi: ${VALID_STATUSES.join(', ')}` }, { status: 400 });
  }

  // Validate note length
  if (note && note.length > 1000) {
    return NextResponse.json({ error: 'Pastaba per ilga (maks. 1000 simbolių).' }, { status: 400 });
  }

  const serviceClient = createServiceRoleClient();

  // Check user role (must be admin or superadmin)
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  if (!profile || (profile.role !== 'admin' && profile.role !== 'superadmin')) {
    return NextResponse.json({ error: 'Tik administratoriai gali keisti trūkumų būseną.' }, { status: 403 });
  }

  const isSuperadmin = profile.role === 'superadmin';

  // Verify finding exists and belongs to user's org
  const { data: finding } = await (isSuperadmin ? serviceClient : supabase)
    .from('findings')
    .select('id, org_id')
    .eq('id', finding_id)
    .single();

  if (!finding) {
    return NextResponse.json({ error: 'Trūkumas nerastas.' }, { status: 404 });
  }

  if (!isSuperadmin && finding.org_id !== profile.org_id) {
    return NextResponse.json({ error: 'Prieiga uždrausta.' }, { status: 403 });
  }

  // Upsert finding status
  const { data: result, error } = await serviceClient
    .from('finding_status')
    .upsert(
      {
        finding_id,
        org_id: finding.org_id,
        status,
        note: note?.trim() || null,
        updated_by: user.id,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'finding_id' },
    )
    .select()
    .single();

  if (error) {
    console.error('Failed to update finding status:', error);
    return NextResponse.json({ error: 'Klaida atnaujinant būseną.' }, { status: 500 });
  }

  // Audit log
  await serviceClient.from('audit_log').insert({
    org_id: finding.org_id,
    user_id: user.id,
    action: 'finding_status_changed',
    details: { finding_id, status, note: note?.trim() || null },
    ip_address: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || null,
  });

  return NextResponse.json({ finding_status: result }, { status: 200, headers: rateLimitHeaders(rl) });
}

/**
 * GET /api/findings/status?org_id=...
 * Get all finding statuses for an organization.
 */
export async function GET(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neprisijungęs.' }, { status: 401 });
  }

  const rl = checkRateLimit(user.id);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rl) },
    );
  }

  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  const { searchParams } = new URL(request.url);
  const orgId = searchParams.get('org_id') || profile?.org_id;

  if (!orgId) {
    return NextResponse.json({ error: 'Trūksta org_id.' }, { status: 400 });
  }

  if (!isSuperadmin && orgId !== profile?.org_id) {
    return NextResponse.json({ error: 'Prieiga uždrausta.' }, { status: 403 });
  }

  const { data: statuses, error } = await (isSuperadmin ? serviceClient : supabase)
    .from('finding_status')
    .select('*')
    .eq('org_id', orgId);

  if (error) {
    return NextResponse.json({ error: 'Klaida gaunant būsenas.' }, { status: 500 });
  }

  return NextResponse.json({ statuses: statuses ?? [] }, { status: 200, headers: rateLimitHeaders(rl) });
}
