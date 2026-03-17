import { NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';

/**
 * GET /api/cron/monthly-scan
 * Vercel Cron handler — runs daily, checks which organizations have
 * auto_scan_enabled and whose auto_scan_day matches today.
 *
 * Security: Requires CRON_SECRET header to prevent unauthorized triggers.
 */
export async function GET(request: Request) {
  // Verify cron secret
  const cronSecret = request.headers.get('authorization')?.replace('Bearer ', '');
  if (cronSecret !== process.env.CRON_SECRET) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const serviceClient = createServiceRoleClient();
  const today = new Date();
  const dayOfMonth = today.getDate();

  // Find organizations that should be scanned today
  const { data: orgs, error } = await serviceClient
    .from('organizations')
    .select('id, name, domain, verified')
    .eq('auto_scan_enabled', true)
    .eq('auto_scan_day', dayOfMonth)
    .eq('verified', true);

  if (error || !orgs) {
    console.error('Cron monthly-scan: failed to query organizations:', error);
    return NextResponse.json({ error: 'Query failed' }, { status: 500 });
  }

  const results = [];

  for (const org of orgs) {
    // Check no active scan exists
    const { data: activeScan } = await serviceClient
      .from('scans')
      .select('id')
      .eq('org_id', org.id)
      .in('status', ['queued', 'running'])
      .limit(1)
      .maybeSingle();

    if (activeScan) {
      results.push({ org_id: org.id, status: 'skipped', reason: 'active_scan_exists' });
      continue;
    }

    // Create scan record
    const { data: scan, error: scanError } = await serviceClient
      .from('scans')
      .insert({
        org_id: org.id,
        scan_type: 'light',
        status: 'queued',
        triggered_by: null, // automated
      })
      .select()
      .single();

    if (scanError || !scan) {
      results.push({ org_id: org.id, status: 'error', reason: scanError?.message });
      continue;
    }

    // Audit log
    await serviceClient.from('audit_log').insert({
      org_id: org.id,
      user_id: null,
      action: 'scan_triggered',
      details: { scan_id: scan.id, trigger: 'scheduled', day_of_month: dayOfMonth },
    });

    // Create notification
    await serviceClient.from('notifications').insert({
      org_id: org.id,
      type: 'scan_started',
      title_lt: 'Mėnesinis skenavimas pradėtas',
      body_lt: `Automatinis mėnesinis skenavimas domeno ${org.domain} pradėtas.`,
      link: `/scans/${scan.id}`,
    });

    // Trigger the actual scan execution asynchronously
    // In production, this would call the scan API internally
    try {
      const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://platform.scanit.lt';
      await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-cron-secret': process.env.CRON_SECRET || '',
        },
        body: JSON.stringify({
          org_id: org.id,
          scan_id: scan.id,
          cron_trigger: true,
        }),
      });
    } catch (err) {
      console.error(`Cron: failed to trigger scan for ${org.domain}:`, err);
    }

    results.push({ org_id: org.id, status: 'triggered', scan_id: scan.id });
  }

  return NextResponse.json({
    date: today.toISOString(),
    day_of_month: dayOfMonth,
    organizations_checked: orgs.length,
    results,
  });
}
