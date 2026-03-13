import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';

const VALID_FIELDS = ['ip_ranges', 'employee_emails', 'subdomains'] as const;
type EnrichmentField = typeof VALID_FIELDS[number];

const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function validateValues(field: EnrichmentField, values: string[]): string | null {
  if (values.length > 500) {
    return 'Maksimalus įrašų skaičius — 500.';
  }

  for (const v of values) {
    if (field === 'ip_ranges') {
      if (!CIDR_REGEX.test(v)) return `Netinkamas CIDR formatas: ${v}`;
      const [ip, prefix] = v.split('/');
      const parts = ip.split('.').map(Number);
      const prefixNum = Number(prefix);
      if (!parts.every((p) => p >= 0 && p <= 255) || prefixNum < 0 || prefixNum > 32) {
        return `Netinkamas CIDR rangą: ${v}`;
      }
    } else if (field === 'employee_emails') {
      if (!EMAIL_REGEX.test(v)) return `Netinkamas el. pašto formatas: ${v}`;
    } else if (field === 'subdomains') {
      if (!DOMAIN_REGEX.test(v)) return `Netinkamas subdomeno formatas: ${v}`;
    }
  }

  return null;
}

export async function POST(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 });
  }

  const rateResult = checkRateLimit(`enrichment:${user.id}`);
  if (!rateResult.allowed) {
    return NextResponse.json(
      { error: 'Per daug užklausų.' },
      { status: 429, headers: rateLimitHeaders(rateResult) },
    );
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  if (!profile?.org_id) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  if (profile.role !== 'admin' && profile.role !== 'superadmin') {
    return NextResponse.json({ error: 'Tik administratoriai gali keisti duomenis.' }, { status: 403 });
  }

  let body: { orgId?: string; field?: string; values?: string[] };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Netinkama užklausa.' }, { status: 400 });
  }

  const { field, values } = body;

  if (!field || !VALID_FIELDS.includes(field as EnrichmentField)) {
    return NextResponse.json({ error: 'Netinkamas laukas.' }, { status: 400 });
  }

  if (!Array.isArray(values)) {
    return NextResponse.json({ error: 'Reikšmės turi būti masyvas.' }, { status: 400 });
  }

  const validationError = validateValues(field as EnrichmentField, values);
  if (validationError) {
    return NextResponse.json({ error: validationError }, { status: 400 });
  }

  const serviceClient = createServiceRoleClient();

  const { error: updateError } = await serviceClient
    .from('organizations')
    .update({ [field]: values })
    .eq('id', profile.org_id);

  if (updateError) {
    return NextResponse.json({ error: 'Klaida išsaugant duomenis.' }, { status: 500 });
  }

  // Audit log
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';

  await serviceClient.from('audit_log').insert({
    org_id: profile.org_id,
    user_id: user.id,
    action: 'enrichment_updated',
    details: { field, count: values.length },
    ip_address: ip,
  });

  return NextResponse.json({
    success: true,
    message: 'Duomenys išsaugoti.',
    field,
    count: values.length,
  });
}
