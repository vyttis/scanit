import { scanShodan } from './shodan';
import { scanHibp } from './hibp';
import { scanSsl } from './ssl';
import { scanMxtoolbox } from './mxtoolbox';
import { scanSecuritytrails } from './securitytrails';
import { scanVirustotal } from './virustotal';
import { scanAbuseipdb } from './abuseipdb';
import { scanUrlscan } from './urlscan';
import type { ScannerFunction, ScannerResult } from './types';

export type { ScannerResult, ScannerFinding } from './types';

/** Max time (ms) any single scanner is allowed to run. */
const SCANNER_TIMEOUT_MS = 30_000;

/**
 * All scanner modules, keyed by module name.
 */
export const scanners: Record<string, ScannerFunction> = {
  shodan: scanShodan,
  hibp: scanHibp,
  ssl: scanSsl,
  mxtoolbox: scanMxtoolbox,
  securitytrails: scanSecuritytrails,
  virustotal: scanVirustotal,
  abuseipdb: scanAbuseipdb,
  urlscan: scanUrlscan,
};

/**
 * Wrap a scanner call with a hard timeout so that DNS lookups,
 * slow APIs, or any other blocking call cannot hang indefinitely.
 */
function withTimeout(
  moduleName: string,
  scanner: ScannerFunction,
  domain: string,
): Promise<ScannerResult> {
  return Promise.race([
    scanner(domain),
    new Promise<ScannerResult>((resolve) =>
      setTimeout(
        () =>
          resolve({
            module: moduleName as ScannerResult['module'],
            success: false,
            findings: [],
            error: `Scanner timed out after ${SCANNER_TIMEOUT_MS / 1000}s`,
          }),
        SCANNER_TIMEOUT_MS,
      ),
    ),
  ]);
}

/**
 * Run all scanners in parallel. Each scanner failure is isolated —
 * a failed scanner returns an error result but does not crash others.
 * Every scanner is wrapped in a hard timeout to guard against hanging
 * DNS lookups or unresponsive APIs.
 */
export async function runAllScanners(domain: string): Promise<ScannerResult[]> {
  const entries = Object.entries(scanners);

  const results = await Promise.allSettled(
    entries.map(([name, scanner]) => withTimeout(name, scanner, domain)),
  );

  return results.map((result, index) => {
    const moduleName = entries[index][0];
    if (result.status === 'fulfilled') {
      return result.value;
    }
    // Promise rejected — scanner crashed
    return {
      module: moduleName as ScannerResult['module'],
      success: false,
      findings: [],
      error: result.reason instanceof Error ? result.reason.message : 'Scanner crashed unexpectedly',
    };
  });
}
