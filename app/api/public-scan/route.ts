import { createServiceRoleClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import { isValidDomain, sanitizeDomain, isValidEmail } from '@/lib/validations';
import { runAllScanners } from '@/lib/scanners';
import type { ScannerFinding } from '@/lib/scanners';

/**
 * In-memory rate limiter for free scans: 3 per day per IP.
 * Key = IP address, value = timestamps of scans today.
 */
const freeScanStore = new Map<string, number[]>();
const FREE_SCAN_LIMIT = 4;
const FREE_SCAN_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

// Cleanup every 30 minutes
setInterval(() => {
  const now = Date.now();
  freeScanStore.forEach((timestamps, key) => {
    const filtered = timestamps.filter((t) => now - t < FREE_SCAN_WINDOW_MS);
    if (filtered.length === 0) {
      freeScanStore.delete(key);
    } else {
      freeScanStore.set(key, filtered);
    }
  });
}, 30 * 60 * 1000);

function checkFreeScanLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  let timestamps = freeScanStore.get(ip) ?? [];
  timestamps = timestamps.filter((t) => now - t < FREE_SCAN_WINDOW_MS);

  if (timestamps.length >= FREE_SCAN_LIMIT) {
    return { allowed: false, remaining: 0 };
  }

  timestamps.push(now);
  freeScanStore.set(ip, timestamps);
  return { allowed: true, remaining: FREE_SCAN_LIMIT - timestamps.length };
}

// Severity weights for risk score calculation
const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 1,
  info: 0,
};

function calculateRiskScore(findings: ScannerFinding[]): number {
  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0),
    0,
  );
  return Math.min(100, raw);
}

export async function POST(request: Request) {
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown';

  // Rate limit: 3 free scans per IP per day
  const rateResult = checkFreeScanLimit(ip);
  if (!rateResult.allowed) {
    return NextResponse.json(
      {
        error:
          'Pasiektas nemokamų skenavimų limitas (4 per dieną). Registruokitės norėdami skenuoti daugiau.',
      },
      { status: 429 },
    );
  }

  let body: { domain?: string; email?: string; consent?: boolean };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Netinkama užklausa.' }, { status: 400 });
  }

  const { domain: rawDomain, email, consent } = body;

  // Validate consent
  if (!consent) {
    return NextResponse.json(
      { error: 'Turite patvirtinti, kad turite teisę atlikti šio domeno patikrą.' },
      { status: 400 },
    );
  }

  // Validate domain
  if (!rawDomain || typeof rawDomain !== 'string') {
    return NextResponse.json({ error: 'Domenas yra privalomas.' }, { status: 400 });
  }

  const domain = sanitizeDomain(rawDomain);
  if (!isValidDomain(domain)) {
    return NextResponse.json(
      { error: 'Netinkamas domeno formatas. Pavyzdys: organizacija.lt' },
      { status: 400 },
    );
  }

  // Validate email if provided
  if (email && typeof email === 'string' && email.trim() && !isValidEmail(email.trim())) {
    return NextResponse.json(
      { error: 'Netinkamas el. pašto formatas.' },
      { status: 400 },
    );
  }

  const serviceClient = createServiceRoleClient();

  // Create public scan record
  const { data: scan, error: insertError } = await serviceClient
    .from('public_scans')
    .insert({
      domain,
      email: email?.trim() || null,
      ip_address: ip,
      status: 'queued',
    })
    .select()
    .single();

  if (insertError || !scan) {
    return NextResponse.json(
      { error: 'Klaida kuriant skenavimo įrašą.' },
      { status: 500 },
    );
  }

  // Run scan in background
  executePublicScan(serviceClient, scan.id, domain).catch((err) => {
    console.error(`Public scan ${scan.id} error:`, err);
  });

  return NextResponse.json({
    id: scan.id,
    status: 'queued',
    message: 'Skenavimas pradėtas.',
  });
}

/**
 * GET endpoint to poll public scan status.
 */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return NextResponse.json({ error: 'Netinkamas ID formatas.' }, { status: 400 });
  }

  const serviceClient = createServiceRoleClient();
  const { data: scan } = await serviceClient
    .from('public_scans')
    .select('id, status, risk_score, critical_count, high_count, medium_count, low_count')
    .eq('id', id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: 'Skenavimas nerastas.' }, { status: 404 });
  }

  return NextResponse.json(scan);
}

/**
 * Run all 8 scanners against the domain. Store only titles + severities
 * in public_scans.results (no sensitive details for free tier).
 */
async function executePublicScan(
  serviceClient: ReturnType<typeof createServiceRoleClient>,
  scanId: string,
  domain: string,
) {
  await serviceClient
    .from('public_scans')
    .update({ status: 'running' })
    .eq('id', scanId);

  try {
    const results = await runAllScanners(domain);

    // Collect all findings (titles + severities only for public storage)
    const allFindings: ScannerFinding[] = results.flatMap((r) => r.findings);

    const publicFindings = allFindings.map((f) => ({
      module: f.module,
      severity: f.severity,
      title_lt: f.title_lt,
    }));

    const riskScore = calculateRiskScore(allFindings);
    const criticalCount = allFindings.filter((f) => f.severity === 'critical').length;
    const highCount = allFindings.filter((f) => f.severity === 'high').length;
    const mediumCount = allFindings.filter((f) => f.severity === 'medium').length;
    const lowCount = allFindings.filter((f) => f.severity === 'low').length;

    const modulesRun = results.map((r) => r.module);

    await serviceClient
      .from('public_scans')
      .update({
        status: 'completed',
        results: {
          findings: publicFindings,
          modules_run: modulesRun,
        },
        risk_score: riskScore,
        critical_count: criticalCount,
        high_count: highCount,
        medium_count: mediumCount,
        low_count: lowCount,
      })
      .eq('id', scanId);
  } catch (err) {
    console.error(`Public scan ${scanId} failed:`, err);
    await serviceClient
      .from('public_scans')
      .update({ status: 'failed' })
      .eq('id', scanId);
  }
}
