import { NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

/**
 * GET /api/notifications
 * List notifications for the current user.
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
      { error: 'Per daug užklausų.' },
      { status: 429, headers: rateLimitHeaders(rl) },
    );
  }

  const { searchParams } = new URL(request.url);
  const unreadOnly = searchParams.get('unread') === 'true';
  const limit = Math.min(parseInt(searchParams.get('limit') || '20', 10), 50);

  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id')
    .eq('id', user.id)
    .single();

  if (!profile?.org_id) {
    return NextResponse.json({ notifications: [], unread_count: 0 }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  // Notifications targeted to this user or to all org users
  let query = supabase
    .from('notifications')
    .select('*')
    .eq('org_id', profile.org_id)
    .or(`user_id.is.null,user_id.eq.${user.id}`)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (unreadOnly) {
    query = query.eq('read', false);
  }

  const { data: notifications, error } = await query;

  if (error) {
    return NextResponse.json({ error: 'Klaida gaunant pranešimus.' }, { status: 500 });
  }

  // Count unread
  const { count } = await supabase
    .from('notifications')
    .select('id', { count: 'exact', head: true })
    .eq('org_id', profile.org_id)
    .or(`user_id.is.null,user_id.eq.${user.id}`)
    .eq('read', false);

  return NextResponse.json({
    notifications: notifications ?? [],
    unread_count: count ?? 0,
  }, { status: 200, headers: rateLimitHeaders(rl) });
}

/**
 * PATCH /api/notifications
 * Mark notifications as read.
 * Body: { id: string } or { mark_all_read: true }
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
      { error: 'Per daug užklausų.' },
      { status: 429, headers: rateLimitHeaders(rl) },
    );
  }

  const body = await request.json().catch(() => null);

  if (body?.mark_all_read) {
    // Mark all as read for this user's org
    const serviceClient = createServiceRoleClient();
    const { data: profile } = await serviceClient
      .from('profiles')
      .select('org_id')
      .eq('id', user.id)
      .single();

    if (!profile?.org_id) {
      return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
    }

    await supabase
      .from('notifications')
      .update({ read: true })
      .eq('org_id', profile.org_id)
      .or(`user_id.is.null,user_id.eq.${user.id}`)
      .eq('read', false);

    return NextResponse.json({ success: true }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  if (body?.id) {
    const { error } = await supabase
      .from('notifications')
      .update({ read: true })
      .eq('id', body.id);

    if (error) {
      return NextResponse.json({ error: 'Klaida.' }, { status: 500 });
    }

    return NextResponse.json({ success: true }, { status: 200, headers: rateLimitHeaders(rl) });
  }

  return NextResponse.json({ error: 'Trūksta id arba mark_all_read.' }, { status: 400 });
}
