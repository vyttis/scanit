import { NextResponse } from 'next/server';
import { createServiceRoleClient } from '@/lib/supabase/server';
import { runAllScanners } from '@/lib/scanners';
import { generateReport } from '@/lib/report/generator';
import type { ScannerOptions } from '@/lib/scanners';

export const maxDuration = 120;

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

    // Execute scan directly using service role (no HTTP round-trip needed)
    try {
      // Mark scan as running
      await serviceClient
        .from('scans')
        .update({ status: 'running', started_at: new Date().toISOString() })
        .eq('id', scan.id);

      // Fetch full org for professional plan fields
      const { data: fullOrg } = await serviceClient
        .from('organizations')
        .select('ip_ranges, subdomains, employee_emails')
        .eq('id', org.id)
        .single();

      const scannerOptions: ScannerOptions = {
        ipRanges: (fullOrg?.ip_ranges as string[] | undefined) ?? undefined,
        subdomains: (fullOrg?.subdomains as string[] | undefined) ?? undefined,
        emails: (fullOrg?.employee_emails as string[] | undefined) ?? undefined,
      };

      const scannerResults = await runAllScanners(org.domain, scannerOptions);

      // Collect all findings from successful scanners
      const allFindings = scannerResults.flatMap((r) => r.findings);
      const failedScanners = scannerResults.filter((r) => !r.success);

      // Store findings
      if (allFindings.length > 0) {
        await serviceClient.from('findings').insert(
          allFindings.map((f) => ({
            scan_id: scan.id,
            org_id: org.id,
            module: f.module,
            severity: f.severity,
            title_lt: f.title_lt,
            description_lt: f.description_lt,
            recommendation_lt: f.recommendation_lt,
            nis2_article: f.nis2_article || null,
            evidence: f.evidence || null,
          }))
        );
      }

      // Mark completed
      await serviceClient
        .from('scans')
        .update({
          status: 'completed',
          completed_at: new Date().toISOString(),
          scanner_errors: failedScanners.length
            ? failedScanners.map((r) => ({ module: r.module, error: r.error ?? 'Unknown error' }))
            : null,
        })
        .eq('id', scan.id);

      // Generate report
      try {
        await generateReport(scan.id);
      } catch (reportErr) {
        console.error(`Cron: report generation failed for ${org.domain}:`, reportErr);
      }
    } catch (err) {
      console.error(`Cron: scan execution failed for ${org.domain}:`, err);
      await serviceClient
        .from('scans')
        .update({ status: 'failed', completed_at: new Date().toISOString() })
        .eq('id', scan.id);
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
