import { createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

const STALE_SCAN_TIMEOUT_MINUTES = 10;

/**
 * Cron job endpoint: cleans up stale scans stuck in 'queued' or 'running' status.
 * Runs every 5 minutes via Vercel Cron.
 * Protected by CRON_SECRET header validation.
 */
export async function GET(request: Request) {
  // Verify cron secret — Vercel sends this header automatically for cron jobs
  const authHeader = request.headers.get('authorization');
  const cronSecret = process.env.CRON_SECRET;

  // SECURITY: Reject if CRON_SECRET is not configured OR if header doesn't match
  if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const serviceClient = createServiceRoleClient();

  const cutoffTime = new Date(Date.now() - STALE_SCAN_TIMEOUT_MINUTES * 60 * 1000).toISOString();

  // Find stale scans: queued/running and started (or created) more than 10 minutes ago
  const { data: staleScans, error: fetchError } = await serviceClient
    .from('scans')
    .select('id, status, started_at, created_at')
    .in('status', ['queued', 'running'])
    .or(`started_at.lt.${cutoffTime},created_at.lt.${cutoffTime}`);

  if (fetchError) {
    console.error('Stale scan cleanup fetch error:', fetchError);
    return NextResponse.json({ error: 'Fetch error' }, { status: 500 });
  }

  if (!staleScans || staleScans.length === 0) {
    return NextResponse.json({ cleaned: 0 });
  }

  const timeoutError = [{ module: 'system', error: 'Skenavimas buvo nutrauktas dėl laiko limito.' }];

  let cleaned = 0;
  for (const scan of staleScans) {
    const { error: updateError } = await serviceClient
      .from('scans')
      .update({
        status: 'failed',
        completed_at: new Date().toISOString(),
        scanner_errors: timeoutError,
      })
      .eq('id', scan.id);

    if (!updateError) {
      cleaned++;
      console.log(`Stale scan cleanup: marked scan ${scan.id} as failed (was ${scan.status})`);
    } else {
      console.error(`Stale scan cleanup: failed to update scan ${scan.id}:`, updateError);
    }
  }

  return NextResponse.json({ cleaned, total: staleScans.length });
}
