import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { sendEmail } from '@/lib/email/send';
import { registrationApprovedHtml } from '@/lib/email/templates/registration-approved';
import { registrationRejectedHtml } from '@/lib/email/templates/registration-rejected';

export async function POST(request: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Neautorizuotas.' }, { status: 401 });
    }

    const serviceClient = createServiceRoleClient();

    // Check superadmin role
    const { data: adminProfile } = await serviceClient
      .from('profiles')
      .select('role')
      .eq('id', user.id)
      .single();

    if (adminProfile?.role !== 'superadmin') {
      return NextResponse.json({ error: 'Draudžiama.' }, { status: 403 });
    }

    const { userId, action } = await request.json();

    if (!userId || !['approve', 'reject'].includes(action)) {
      return NextResponse.json({ error: 'Neteisingi parametrai.' }, { status: 400 });
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';

    // Update profile status
    const { error: updateError } = await serviceClient
      .from('profiles')
      .update({ status: newStatus })
      .eq('id', userId);

    if (updateError) {
      console.error('Profile update error:', updateError.message);
      return NextResponse.json({ error: 'Klaida atnaujinant vartotoją.' }, { status: 500 });
    }

    // Get user info for email
    const { data: profile } = await serviceClient
      .from('profiles')
      .select('first_name, last_name')
      .eq('id', userId)
      .single();

    const { data: authUser } = await serviceClient.auth.admin.getUserById(userId);
    const userEmail = authUser?.user?.email;

    if (userEmail && profile) {
      try {
        if (action === 'approve') {
          await sendEmail({
            to: userEmail,
            subject: 'scanit.lt — Paskyra patvirtinta',
            html: registrationApprovedHtml({
              firstName: profile.first_name || '',
              lastName: profile.last_name || '',
            }),
          });
        } else {
          await sendEmail({
            to: userEmail,
            subject: 'scanit.lt — Registracija atmesta',
            html: registrationRejectedHtml({
              firstName: profile.first_name || '',
              lastName: profile.last_name || '',
            }),
          });
        }
      } catch (emailError) {
        console.error('Email sending error:', emailError);
      }
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error('Admin action error:', err);
    return NextResponse.json({ error: 'Vidinė serverio klaida.' }, { status: 500 });
  }
}
