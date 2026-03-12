import { NextRequest, NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';

export async function POST(request: NextRequest) {
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

    // Find valid token
    const { data: tokenRecord, error: tokenError } = await supabase
      .from('password_reset_tokens')
      .select('*')
      .eq('token', token)
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

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error('Password reset confirm error:', err);
    return NextResponse.json(
      { error: 'Vidinė serverio klaida.' },
      { status: 500 }
    );
  }
}
