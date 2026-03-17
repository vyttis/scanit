import { NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';
import { calculateSla } from '@/lib/utils/sla';
import type { FindingSeverity } from '@/types/database';

/**
 * GET /api/cron/sla-alerts
 * Daily cron — checks for findings approaching SLA deadline (3 days)
 * and creates in-app notifications + optional email alerts.
 */
export async function GET(request: Request) {
  const cronSecret = request.headers.get('authorization')?.replace('Bearer ', '');
  if (cronSecret !== process.env.CRON_SECRET) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const serviceClient = createServiceRoleClient();

  // Get all organizations
  const { data: orgs } = await serviceClient
    .from('organizations')
    .select('id, name, domain, contact_email')
    .eq('verified', true);

  if (!orgs) {
    return NextResponse.json({ error: 'Failed to fetch orgs' }, { status: 500 });
  }

  let totalAlerts = 0;

  for (const org of orgs) {
    // Get latest completed scan
    const { data: latestScan } = await serviceClient
      .from('scans')
      .select('id')
      .eq('org_id', org.id)
      .eq('status', 'completed')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!latestScan) continue;

    // Get findings from latest scan
    const { data: findings } = await serviceClient
      .from('findings')
      .select('id, severity, created_at')
      .eq('scan_id', latestScan.id)
      .neq('severity', 'info');

    if (!findings || findings.length === 0) continue;

    // Get existing statuses
    const findingIds = findings.map((f) => f.id);
    const { data: statuses } = await serviceClient
      .from('finding_status')
      .select('finding_id, status')
      .in('finding_id', findingIds);

    const statusMap = new Map((statuses ?? []).map((s) => [s.finding_id, s.status]));

    // Check SLA for open/in_progress findings
    const expiringSoon = [];
    const overdue = [];

    for (const f of findings) {
      const fStatus = statusMap.get(f.id) || 'open';
      if (fStatus !== 'open' && fStatus !== 'in_progress') continue;

      const sla = calculateSla(f.severity as FindingSeverity, f.created_at);
      if (!sla) continue;

      if (sla.isOverdue) {
        overdue.push(f);
      } else if (sla.isExpiringSoon) {
        expiringSoon.push(f);
      }
    }

    // Create notifications for expiring findings
    if (expiringSoon.length > 0) {
      await serviceClient.from('notifications').insert({
        org_id: org.id,
        type: 'sla_expiring',
        title_lt: `${expiringSoon.length} trūkumų terminas baigiasi per 3 dienas`,
        body_lt: `Organizacija ${org.name} turi ${expiringSoon.length} trūkumų, kurių SLA terminas baigiasi artimiausiomis dienomis.`,
        link: '/dashboard',
      });
      totalAlerts++;
    }

    if (overdue.length > 0) {
      await serviceClient.from('notifications').insert({
        org_id: org.id,
        type: 'sla_overdue',
        title_lt: `${overdue.length} trūkumų terminas praėjęs`,
        body_lt: `Organizacija ${org.name} turi ${overdue.length} trūkumų, kurių SLA terminas jau praėjęs. Būtina skubiai imtis veiksmų.`,
        link: '/dashboard',
      });
      totalAlerts++;
    }
  }

  return NextResponse.json({
    organizations_checked: orgs.length,
    alerts_created: totalAlerts,
  });
}
