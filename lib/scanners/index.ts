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
 * Run all scanners in parallel. Each scanner failure is isolated —
 * a failed scanner returns an error result but does not crash others.
 */
export async function runAllScanners(domain: string): Promise<ScannerResult[]> {
  const results = await Promise.allSettled(
    Object.values(scanners).map((scanner) => scanner(domain)),
  );

  return results.map((result, index) => {
    const moduleName = Object.keys(scanners)[index];
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
