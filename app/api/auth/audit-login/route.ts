import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

/**
 * POST /api/auth/audit-login — Log a successful login event.
 * Called by the login page after successful authentication.
 */
export async function POST(request: NextRequest) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting to prevent audit log flooding
  const rateResult = checkRateLimit(`audit-login:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';

  const serviceClient = createServiceRoleClient();

  // Get user's org_id for audit log
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id')
    .eq('id', user.id)
    .single();

  await serviceClient.from('audit_log').insert({
    org_id: profile?.org_id || null,
    user_id: user.id,
    action: 'login',
    details: { email: user.email },
    ip_address: ip,
  });

  return NextResponse.json({ success: true });
}
