import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

/**
 * POST /api/auth/audit-logout — Log a logout event before client-side sign-out.
 */
export async function POST(request: NextRequest) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting
  const rateResult = checkRateLimit(`audit-logout:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';

  const serviceClient = createServiceRoleClient();

  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id')
    .eq('id', user.id)
    .single();

  await serviceClient.from('audit_log').insert({
    org_id: profile?.org_id || null,
    user_id: user.id,
    action: 'logout',
    details: {},
    ip_address: ip,
  });

  return NextResponse.json({ success: true });
}
