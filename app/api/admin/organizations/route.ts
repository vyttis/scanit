import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { checkRateLimit, rateLimitHeaders } from '@/lib/rate-limit';
import { isValidDomain, sanitizeDomain, isValidEmail, isValidUuid } from '@/lib/validations';

async function requireSuperadmin(request: Request) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return { error: NextResponse.json({ error: 'Neautorizuota.' }, { status: 401 }) };
  }

  const rateResult = checkRateLimit(`admin-orgs:${user.id}`);
  if (!rateResult.allowed) {
    return {
      error: NextResponse.json(
        { error: 'Per daug užklausų. Palaukite minutę.' },
        { status: 429, headers: rateLimitHeaders(rateResult) },
      ),
    };
  }

  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  if (profile?.role !== 'superadmin') {
    return { error: NextResponse.json({ error: 'Prieiga uždrausta.' }, { status: 403 }) };
  }

  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') || 'unknown';

  return { user, serviceClient, ip };
}

// POST — Create new organization
export async function POST(request: Request) {
  const auth = await requireSuperadmin(request);
  if ('error' in auth && auth.error instanceof NextResponse) return auth.error;
  const { user, serviceClient, ip } = auth as { user: { id: string }; serviceClient: ReturnType<typeof createServiceRoleClient>; ip: string };

  const body = await request.json().catch(() => null);
  if (!body) {
    return NextResponse.json({ error: 'Netinkamas užklausos formatas.' }, { status: 400 });
  }

  const { name, domain, contact_email, sector, verified } = body;

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return NextResponse.json({ error: 'Pavadinimas privalomas (min. 2 simboliai).' }, { status: 400 });
  }

  if (!domain || !isValidDomain(sanitizeDomain(domain))) {
    return NextResponse.json({ error: 'Netinkamas domeno formatas.' }, { status: 400 });
  }

  if (!contact_email || !isValidEmail(contact_email)) {
    return NextResponse.json({ error: 'Netinkamas el. pašto formatas.' }, { status: 400 });
  }

  const cleanDomain = sanitizeDomain(domain);

  // Check for duplicate domain
  const { data: existing } = await serviceClient
    .from('organizations')
    .select('id')
    .eq('domain', cleanDomain)
    .single();

  if (existing) {
    return NextResponse.json({ error: 'Organizacija su šiuo domenu jau egzistuoja.' }, { status: 409 });
  }

  const { data: org, error: insertError } = await serviceClient
    .from('organizations')
    .insert({
      name: name.trim(),
      domain: cleanDomain,
      contact_email: contact_email.trim(),
      sector: sector || null,
      verified: verified === true,
    })
    .select()
    .single();

  if (insertError) {
    return NextResponse.json({ error: 'Klaida kuriant organizaciją.' }, { status: 500 });
  }

  // Audit log
  await serviceClient.from('audit_log').insert({
    org_id: org.id,
    user_id: user.id,
    action: 'org_created',
    details: { name: org.name, domain: org.domain, verified: org.verified },
    ip_address: ip,
  });

  return NextResponse.json({ organization: org }, { status: 201 });
}

// PATCH — Update organization (verify, suspend, unsuspend, edit)
export async function PATCH(request: Request) {
  const auth = await requireSuperadmin(request);
  if ('error' in auth && auth.error instanceof NextResponse) return auth.error;
  const { user, serviceClient, ip } = auth as { user: { id: string }; serviceClient: ReturnType<typeof createServiceRoleClient>; ip: string };

  const body = await request.json().catch(() => null);
  if (!body || !body.id || !isValidUuid(body.id)) {
    return NextResponse.json({ error: 'Trūksta organizacijos ID.' }, { status: 400 });
  }

  const { id, action, ...fields } = body;

  // Verify org exists
  const { data: org } = await serviceClient
    .from('organizations')
    .select('*')
    .eq('id', id)
    .single();

  if (!org) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  let updateData: Record<string, unknown> = {};
  let auditAction = 'org_updated';
  let auditDetails: Record<string, unknown> = {};

  switch (action) {
    case 'verify':
      updateData = { verified: true };
      auditAction = 'org_verified';
      auditDetails = { domain: org.domain };
      break;

    case 'unverify':
      updateData = { verified: false };
      auditAction = 'org_unverified';
      auditDetails = { domain: org.domain };
      break;

    case 'change_plan': {
      const validPlans = ['free', 'basic', 'professional'];
      const newPlan = fields.plan;
      if (!newPlan || !validPlans.includes(newPlan)) {
        return NextResponse.json({ error: 'Netinkamas planas.' }, { status: 400 });
      }
      // Update plan on ALL profiles belonging to this organization
      const { error: planError } = await serviceClient
        .from('profiles')
        .update({ plan: newPlan })
        .eq('org_id', id);
      if (planError) {
        return NextResponse.json({ error: 'Klaida keičiant planą.' }, { status: 500 });
      }
      auditAction = 'org_plan_changed';
      auditDetails = { new_plan: newPlan, org_name: org.name };
      // Return org as-is (plan is on profiles, not organizations)
      await serviceClient.from('audit_log').insert({
        org_id: id,
        user_id: user.id,
        action: auditAction,
        details: auditDetails,
        ip_address: ip,
      });
      return NextResponse.json({ success: true, organization: { ...org, plan: newPlan } });
    }

    case 'update':
      if (fields.name && typeof fields.name === 'string' && fields.name.trim().length >= 2) {
        updateData.name = fields.name.trim();
      }
      if (fields.contact_email && isValidEmail(fields.contact_email)) {
        updateData.contact_email = fields.contact_email.trim();
      }
      if (fields.sector !== undefined) {
        updateData.sector = fields.sector || null;
      }
      if (Object.keys(updateData).length === 0) {
        return NextResponse.json({ error: 'Nėra ką atnaujinti.' }, { status: 400 });
      }
      auditAction = 'org_updated';
      auditDetails = { changes: updateData };
      break;

    default:
      return NextResponse.json({ error: 'Nežinomas veiksmas.' }, { status: 400 });
  }

  const { data: updatedOrg, error: updateError } = await serviceClient
    .from('organizations')
    .update(updateData)
    .eq('id', id)
    .select()
    .single();

  if (updateError || !updatedOrg) {
    return NextResponse.json({ error: 'Klaida atnaujinant organizaciją.' }, { status: 500 });
  }

  await serviceClient.from('audit_log').insert({
    org_id: id,
    user_id: user.id,
    action: auditAction,
    details: auditDetails,
    ip_address: ip,
  });

  return NextResponse.json({ success: true, organization: updatedOrg });
}

// DELETE — Delete organization
export async function DELETE(request: Request) {
  const auth = await requireSuperadmin(request);
  if ('error' in auth && auth.error instanceof NextResponse) return auth.error;
  const { user, serviceClient, ip } = auth as { user: { id: string }; serviceClient: ReturnType<typeof createServiceRoleClient>; ip: string };

  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id || !isValidUuid(id)) {
    return NextResponse.json({ error: 'Trūksta organizacijos ID.' }, { status: 400 });
  }

  const { data: org } = await serviceClient
    .from('organizations')
    .select('id, name, domain')
    .eq('id', id)
    .single();

  if (!org) {
    return NextResponse.json({ error: 'Organizacija nerasta.' }, { status: 404 });
  }

  // Audit log BEFORE deletion (so we have the org_id reference)
  await serviceClient.from('audit_log').insert({
    org_id: id,
    user_id: user.id,
    action: 'org_deleted',
    details: { name: org.name, domain: org.domain },
    ip_address: ip,
  });

  // Delete organization — CASCADE will remove scans, findings, reports
  const { error: deleteError } = await serviceClient
    .from('organizations')
    .delete()
    .eq('id', id);

  if (deleteError) {
    return NextResponse.json({ error: 'Klaida trinant organizaciją.' }, { status: 500 });
  }

  return NextResponse.json({ success: true });
}
