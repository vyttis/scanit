import { NextRequest, NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';
import { isValidEmail } from '@/lib/validations';
import { sendEmail } from '@/lib/email/send';
import { passwordResetHtml } from '@/lib/email/templates/password-reset';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import crypto from 'crypto';

export async function POST(request: NextRequest) {
  // Rate limiting by IP to prevent brute-force
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';
  const rateResult = checkRateLimit(`password-reset:${ip}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  try {
    const { email } = await request.json();

    if (!email || !isValidEmail(email)) {
      return NextResponse.json(
        { error: 'Neteisingas el. pašto formatas.' },
        { status: 400 }
      );
    }

    const supabase = createServiceRoleClient();

    // Look up user by email (paginated listUsers would miss users beyond page 1)
    const { data: users } = await supabase.auth.admin.listUsers({
      page: 1,
      perPage: 1,
      filter: email.toLowerCase(),
    } as Parameters<typeof supabase.auth.admin.listUsers>[0]);
    const user = users?.users?.[0];

    // Always return success to prevent email enumeration
    if (!user) {
      return NextResponse.json({ success: true });
    }

    // Get profile for first name
    const { data: profile } = await supabase
      .from('profiles')
      .select('first_name')
      .eq('id', user.id)
      .single();

    // Generate secure token — store hashed, send plaintext in email
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store hashed token (defense-in-depth: if DB is compromised, tokens are unusable)
    const { error: tokenError } = await supabase
      .from('password_reset_tokens')
      .insert({
        user_id: user.id,
        token: tokenHash,
        expires_at: expiresAt.toISOString(),
      });

    if (tokenError) {
      console.error('Token insert error:', tokenError.message);
      return NextResponse.json(
        { error: 'Vidinė klaida. Bandykite dar kartą.' },
        { status: 500 }
      );
    }

    // Send password reset email via Resend
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://platform.scanit.lt';
    const resetLink = `${appUrl}/naujas-slaptazodis?token=${token}`;

    await sendEmail({
      to: email,
      subject: 'scanit.lt — Slaptažodžio keitimas',
      html: passwordResetHtml({
        firstName: profile?.first_name || 'Vartotojau',
        resetLink,
      }),
    });

    // Audit log: password reset requested
    const { data: userProfile } = await supabase
      .from('profiles')
      .select('org_id')
      .eq('id', user.id)
      .single();

    await supabase.from('audit_log').insert({
      org_id: userProfile?.org_id || null,
      user_id: user.id,
      action: 'password_reset_requested',
      details: {},
      ip_address: ip,
    });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error('Password reset error:', err);
    return NextResponse.json(
      { error: 'Vidinė serverio klaida.' },
      { status: 500 }
    );
  }
}
