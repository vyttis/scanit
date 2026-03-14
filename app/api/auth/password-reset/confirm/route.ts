import { NextRequest, NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import crypto from 'crypto';

export async function POST(request: NextRequest) {
  // Rate limiting by IP to prevent token brute-force
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';
  const rateResult = checkRateLimit(`password-confirm:${ip}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  try {
    const { token, password } = await request.json();

    if (!token || !password) {
      return NextResponse.json(
        { error: 'Trūksta privalomų laukų.' },
        { status: 400 }
      );
    }

    if (password.length < 12) {
      return NextResponse.json(
        { error: 'Slaptažodis turi būti ne trumpesnis nei 12 simbolių.' },
        { status: 400 }
      );
    }

    const supabase = createServiceRoleClient();

    // Hash the incoming token to match against stored hash
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Find valid token by hash
    const { data: tokenRecord, error: tokenError } = await supabase
      .from('password_reset_tokens')
      .select('*')
      .eq('token', tokenHash)
      .eq('used', false)
      .single();

    if (tokenError || !tokenRecord) {
      return NextResponse.json(
        { error: 'Nuoroda negaliojanti arba pasibaigusi.' },
        { status: 400 }
      );
    }

    // Check expiry
    if (new Date(tokenRecord.expires_at) < new Date()) {
      return NextResponse.json(
        { error: 'Nuoroda pasibaigusi. Prašome iš naujo pateikti prašymą.' },
        { status: 400 }
      );
    }

    // Update password via Supabase admin API
    const { error: updateError } = await supabase.auth.admin.updateUserById(
      tokenRecord.user_id,
      { password }
    );

    if (updateError) {
      console.error('Password update error:', updateError.message);
      return NextResponse.json(
        { error: 'Klaida keičiant slaptažodį. Bandykite dar kartą.' },
        { status: 500 }
      );
    }

    // Mark token as used
    await supabase
      .from('password_reset_tokens')
      .update({ used: true })
      .eq('id', tokenRecord.id);

    // Audit log: password reset completed
    const { data: userProfile } = await supabase
      .from('profiles')
      .select('org_id')
      .eq('id', tokenRecord.user_id)
      .single();

    await supabase.from('audit_log').insert({
      org_id: userProfile?.org_id || null,
      user_id: tokenRecord.user_id,
      action: 'password_reset_completed',
      details: {},
      ip_address: ip,
    });

    // Get user email for auto-login
    const { data: authUser } = await supabase.auth.admin.getUserById(tokenRecord.user_id);
    const userEmail = authUser?.user?.email;

    return NextResponse.json({ success: true, email: userEmail || null });
  } catch (err) {
    console.error('Password reset confirm error:', err);
    return NextResponse.json(
      { error: 'Vidinė serverio klaida.' },
      { status: 500 }
    );
  }
}
