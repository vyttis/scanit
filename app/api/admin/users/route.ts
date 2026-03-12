import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { sendEmail } from '@/lib/email/send';
import { registrationApprovedHtml } from '@/lib/email/templates/registration-approved';
import { registrationRejectedHtml } from '@/lib/email/templates/registration-rejected';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import { isValidUuid } from '@/lib/validations';

export async function POST(request: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Neautorizuotas.' }, { status: 401 });
    }

    // Rate limiting
    const rateResult = checkRateLimit(`admin-users:${user.id}`);
    if (!rateResult.allowed) {
      return NextResponse.json(
        { error: 'Per daug užklausų. Palaukite minutę.' },
        { status: 429, headers: rateLimitHeaders(rateResult) },
      );
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

    const body = await request.json();
    const { userId, action, role: newRole } = body;

    if (!userId || typeof userId !== 'string' || !isValidUuid(userId)) {
      return NextResponse.json({ error: 'Netinkamas vartotojo ID formatas.' }, { status: 400 });
    }

    if (!['approve', 'reject', 'change_role', 'suspend'].includes(action)) {
      return NextResponse.json({ error: 'Neteisingi parametrai.' }, { status: 400 });
    }

    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      request.headers.get('x-real-ip') || 'unknown';

    // Handle role change
    if (action === 'change_role') {
      if (!newRole || !['admin', 'viewer'].includes(newRole)) {
        return NextResponse.json({ error: 'Netinkama rolė.' }, { status: 400 });
      }

      // Prevent changing superadmin role
      const { data: targetProfile } = await serviceClient
        .from('profiles')
        .select('role')
        .eq('id', userId)
        .single();

      if (targetProfile?.role === 'superadmin') {
        return NextResponse.json({ error: 'Negalima keisti superadmino rolės.' }, { status: 400 });
      }

      const { error: roleError } = await serviceClient
        .from('profiles')
        .update({ role: newRole })
        .eq('id', userId);

      if (roleError) {
        return NextResponse.json({ error: 'Klaida keičiant rolę.' }, { status: 500 });
      }

      await serviceClient.from('audit_log').insert({
        org_id: null,
        user_id: user.id,
        action: 'role_changed',
        details: { target_user_id: userId, new_role: newRole },
        ip_address: ip,
      });

      return NextResponse.json({ success: true });
    }

    // Handle suspend
    if (action === 'suspend') {
      const { data: targetProfile } = await serviceClient
        .from('profiles')
        .select('role')
        .eq('id', userId)
        .single();

      if (targetProfile?.role === 'superadmin') {
        return NextResponse.json({ error: 'Negalima sustabdyti superadmino.' }, { status: 400 });
      }

      const { error: suspendError } = await serviceClient
        .from('profiles')
        .update({ status: 'suspended' })
        .eq('id', userId);

      if (suspendError) {
        return NextResponse.json({ error: 'Klaida sustabdant vartotoją.' }, { status: 500 });
      }

      await serviceClient.from('audit_log').insert({
        org_id: null,
        user_id: user.id,
        action: 'user_suspended',
        details: { target_user_id: userId },
        ip_address: ip,
      });

      return NextResponse.json({ success: true });
    }

    // Handle approve/reject
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

    // Audit log: admin approval/rejection
    await serviceClient.from('audit_log').insert({
      org_id: null,
      user_id: user.id,
      action: action === 'approve' ? 'user_approved' : 'user_rejected',
      details: { target_user_id: userId, target_email: userEmail || null },
      ip_address: ip,
    });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error('Admin action error:', err);
    return NextResponse.json({ error: 'Vidinė serverio klaida.' }, { status: 500 });
  }
}
