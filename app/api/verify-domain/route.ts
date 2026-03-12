import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { isValidDomain, sanitizeDomain, isValidEmail, generateVerificationToken } from '@/lib/validations';
import { resolve } from 'dns/promises';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

export async function POST(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  // Rate limiting: max 10 requests/minute per user
  const rateResult = checkRateLimit(`verify-domain:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų. Palaukite minutę ir bandykite dar kartą.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Netinkama užklausa.' }, { status: 400 });
  }

  const { action } = body;

  if (action === 'register') {
    return handleRegister(user.id, body as { name: string; domain: string; contact_email: string; sector: string | null });
  } else if (action === 'verify') {
    return handleVerify(user.id);
  }

  return NextResponse.json({ error: 'Nežinomas veiksmas.' }, { status: 400 });
}

async function handleRegister(
  userId: string,
  body: { name: string; domain: string; contact_email: string; sector: string | null },
) {
  const serviceClient = createServiceRoleClient();

  const domain = sanitizeDomain(body.domain);

  if (!body.name?.trim()) {
    return NextResponse.json({ error: 'Įveskite organizacijos pavadinimą.' }, { status: 400 });
  }

  if (!isValidDomain(domain)) {
    return NextResponse.json({ error: 'Neteisingas domeno formatas.' }, { status: 400 });
  }

  if (!isValidEmail(body.contact_email)) {
    return NextResponse.json({ error: 'Neteisingas el. pašto formatas.' }, { status: 400 });
  }

  // Check if domain already registered
  const { data: existing } = await serviceClient
    .from('organizations')
    .select('id')
    .eq('domain', domain)
    .single();

  if (existing) {
    return NextResponse.json({ error: 'Šis domenas jau užregistruotas.' }, { status: 409 });
  }

  // Check user doesn't already have an org
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id')
    .eq('id', userId)
    .single();

  if (profile?.org_id) {
    return NextResponse.json({ error: 'Jūs jau turite organizaciją.' }, { status: 409 });
  }

  const verificationToken = generateVerificationToken();

  // Create organization
  const { data: org, error: orgError } = await serviceClient
    .from('organizations')
    .insert({
      name: body.name.trim(),
      domain,
      contact_email: body.contact_email.trim(),
      sector: body.sector,
      verification_token: verificationToken,
      verified: false,
    })
    .select()
    .single();

  if (orgError) {
    return NextResponse.json({ error: 'Klaida registruojant organizaciją.' }, { status: 500 });
  }

  // Link user to organization
  const { error: profileError } = await serviceClient
    .from('profiles')
    .update({ org_id: org.id, role: 'admin' })
    .eq('id', userId);

  if (profileError) {
    return NextResponse.json({ error: 'Klaida susiejant paskyrą su organizacija.' }, { status: 500 });
  }

  // Audit log
  await serviceClient.from('audit_log').insert({
    org_id: org.id,
    user_id: userId,
    action: 'organization_registered',
    details: { domain, name: body.name.trim() },
  });

  return NextResponse.json({ success: true, org_id: org.id });
}

async function handleVerify(userId: string) {
  const serviceClient = createServiceRoleClient();

  // Get user's organization
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id')
    .eq('id', userId)
    .single();

  if (!profile?.org_id) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  const { data: org } = await serviceClient
    .from('organizations')
    .select('*')
    .eq('id', profile.org_id)
    .single();

  if (!org) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  if (org.verified) {
    return NextResponse.json({ verified: true });
  }

  // Perform DNS TXT record lookup
  try {
    const records = await resolve(org.domain, 'TXT');
    const flatRecords = records.map((r: string[]) => r.join(''));
    const found = flatRecords.some((r: string) => r.includes(org.verification_token));

    if (found) {
      await serviceClient
        .from('organizations')
        .update({ verified: true })
        .eq('id', org.id);

      // Audit log
      await serviceClient.from('audit_log').insert({
        org_id: org.id,
        user_id: userId,
        action: 'domain_verified',
        details: { domain: org.domain },
      });

      return NextResponse.json({ verified: true });
    }

    return NextResponse.json(
      { verified: false, error: 'DNS TXT įrašas nerastas. Patikrinkite, ar teisingai pridėjote įrašą ir ar DNS pakeitimai įsigaliojo.' },
      { status: 200 },
    );
  } catch {
    return NextResponse.json(
      { verified: false, error: 'Nepavyko patikrinti DNS įrašų. Bandykite dar kartą vėliau.' },
      { status: 200 },
    );
  }
}
