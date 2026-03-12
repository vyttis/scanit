import { NextRequest, NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';
import { isValidEmail, isValidDomain } from '@/lib/validations';
import { sendEmail } from '@/lib/email/send';
import { registrationPendingHtml } from '@/lib/email/templates/registration-pending';
import { adminNewUserHtml } from '@/lib/email/templates/admin-new-user';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

const BLOCKED_DOMAINS = [
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
  'mail.ru', 'inbox.lt', 'one.lt', 'yahoo.lt', 'live.com',
  'icloud.com', 'protonmail.com', 'yandex.ru',
];

export async function POST(request: NextRequest) {
  // Rate limiting by IP to prevent registration spam
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';
  const rateResult = checkRateLimit(`register:${ip}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  try {
    const body = await request.json();
    const { firstName, lastName, email, orgName, orgWebsite, password } = body;

    // Validate required fields
    if (!firstName || !lastName || !email || !orgName || !orgWebsite || !password) {
      return NextResponse.json(
        { error: 'Visi laukai yra privalomi.' },
        { status: 400 }
      );
    }

    // Validate email format
    if (!isValidEmail(email)) {
      return NextResponse.json(
        { error: 'Neteisingas el. pašto formatas.' },
        { status: 400 }
      );
    }

    // Validate domain format
    if (!isValidDomain(orgWebsite)) {
      return NextResponse.json(
        { error: 'Neteisingas svetainės domeno formatas.' },
        { status: 400 }
      );
    }

    // Block public email providers
    const emailDomain = email.split('@')[1]?.toLowerCase();
    if (BLOCKED_DOMAINS.includes(emailDomain)) {
      return NextResponse.json(
        { error: 'Registracija galima tik su įmonės el. paštu.' },
        { status: 400 }
      );
    }

    // Domain match validation
    if (emailDomain !== orgWebsite.toLowerCase()) {
      return NextResponse.json(
        { error: 'El. pašto adresas turi sutapti su organizacijos svetainės domenu.' },
        { status: 400 }
      );
    }

    // Password validation
    if (password.length < 12) {
      return NextResponse.json(
        { error: 'Slaptažodis turi būti ne trumpesnis nei 12 simbolių.' },
        { status: 400 }
      );
    }

    const supabase = createServiceRoleClient();

    // Create user in Supabase Auth (no email confirmation — we handle manually)
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true, // Mark email as confirmed since we validate domain match
      user_metadata: {
        first_name: firstName,
        last_name: lastName,
        org_name: orgName,
        org_website: orgWebsite,
      },
    });

    if (authError) {
      if (authError.message.includes('already been registered') || authError.message.includes('already exists')) {
        return NextResponse.json(
          { error: 'Šis el. pašto adresas jau registruotas.' },
          { status: 409 }
        );
      }
      console.error('Auth error:', authError.message);
      return NextResponse.json(
        { error: 'Registracijos klaida. Bandykite dar kartą.' },
        { status: 500 }
      );
    }

    const userId = authData.user.id;

    // Check if organization with this domain already exists
    const { data: existingOrg } = await supabase
      .from('organizations')
      .select('id')
      .eq('domain', orgWebsite.toLowerCase())
      .single();

    let orgId: string;

    if (existingOrg) {
      orgId = existingOrg.id;
    } else {
      // Create organization
      const { data: newOrg, error: orgError } = await supabase
        .from('organizations')
        .insert({
          name: orgName,
          domain: orgWebsite.toLowerCase(),
          contact_email: email,
        })
        .select('id')
        .single();

      if (orgError) {
        console.error('Org creation error:', orgError.message);
        // Clean up: delete the auth user
        await supabase.auth.admin.deleteUser(userId);
        return NextResponse.json(
          { error: 'Klaida kuriant organizaciją. Bandykite dar kartą.' },
          { status: 500 }
        );
      }

      orgId = newOrg.id;
    }

    // Update profile with name, org, and pending status
    const { error: profileError } = await supabase
      .from('profiles')
      .update({
        first_name: firstName,
        last_name: lastName,
        org_id: orgId,
        status: 'pending',
      })
      .eq('id', userId);

    if (profileError) {
      console.error('Profile update error:', profileError.message);
    }

    // Send emails via Resend
    const now = new Date().toLocaleString('lt-LT', { timeZone: 'Europe/Vilnius' });

    try {
      // Email to user: registration pending
      await sendEmail({
        to: email,
        subject: 'scanit.lt — Registracija gauta',
        html: registrationPendingHtml({ firstName, lastName, organizationName: orgName }),
      });

      // Email to superadmin: new user notification
      const superadminEmail = process.env.SUPERADMIN_EMAIL;
      if (superadminEmail) {
        await sendEmail({
          to: superadminEmail,
          subject: `scanit.lt — Naujas vartotojas: ${firstName} ${lastName} (${orgName})`,
          html: adminNewUserHtml({
            firstName,
            lastName,
            email,
            organizationName: orgName,
            organizationWebsite: orgWebsite,
            registeredAt: now,
          }),
        });
      }
    } catch (emailError) {
      // Log but don't fail registration if email sending fails
      console.error('Email sending error:', emailError);
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error('Registration error:', err);
    return NextResponse.json(
      { error: 'Vidinė serverio klaida.' },
      { status: 500 }
    );
  }
}
