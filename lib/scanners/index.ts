import { scanShodan } from './shodan';
import { scanHibp } from './hibp';
import { scanSsl } from './ssl';
import { scanMxtoolbox } from './mxtoolbox';
import { scanSecuritytrails } from './securitytrails';
import { scanVirustotal } from './virustotal';
import { scanAbuseipdb } from './abuseipdb';
import { scanUrlscan } from './urlscan';
import type { ScannerFunction, ScannerResult, ScannerOptions } from './types';

export type { ScannerResult, ScannerFinding, ScannerOptions } from './types';

/** Max time (ms) any single scanner is allowed to run.
 * Light scan: 100s (SSL Labs needs up to 90s).
 * Deep scan: 150s (extra headroom for IP/subdomain/email checks). */
const SCANNER_TIMEOUT_LIGHT_MS = 100_000;
const SCANNER_TIMEOUT_DEEP_MS = 150_000;

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
  options?: ScannerOptions,
): Promise<ScannerResult> {
  const hasExtraInputs = !!(options?.ipRanges?.length || options?.subdomains?.length || options?.emails?.length);
  const timeoutMs = hasExtraInputs ? SCANNER_TIMEOUT_DEEP_MS : SCANNER_TIMEOUT_LIGHT_MS;

  return Promise.race([
    scanner(domain, options),
    new Promise<ScannerResult>((resolve) =>
      setTimeout(
        () =>
          resolve({
            module: moduleName as ScannerResult['module'],
            success: false,
            findings: [],
            error: `Scanner timed out after ${timeoutMs / 1000}s`,
          }),
        timeoutMs,
      ),
    ),
  ]);
}

/**
 * Check which API keys are available at runtime (values not logged).
 */
export function checkScannerEnvVars(): Record<string, boolean> {
  return {
    SHODAN_API_KEY: !!process.env.SHODAN_API_KEY,
    HIBP_API_KEY: !!process.env.HIBP_API_KEY,
    SECURITYTRAILS_API_KEY: !!process.env.SECURITYTRAILS_API_KEY,
    VIRUSTOTAL_API_KEY: !!process.env.VIRUSTOTAL_API_KEY,
    ABUSEIPDB_API_KEY: !!process.env.ABUSEIPDB_API_KEY,
    URLSCAN_API_KEY: !!process.env.URLSCAN_API_KEY,
    ANTHROPIC_API_KEY: !!process.env.ANTHROPIC_API_KEY,
  };
}

/**
 * Run all scanners in parallel. Each scanner failure is isolated —
 * a failed scanner returns an error result but does not crash others.
 * Every scanner is wrapped in a hard timeout to guard against hanging
 * DNS lookups or unresponsive APIs.
 *
 * @param domain - The primary domain to scan
 * @param options - Optional extra parameters (IP ranges, subdomains, emails) for professional plan
 */
export async function runAllScanners(domain: string, options?: ScannerOptions): Promise<ScannerResult[]> {
  // Diagnostic: log which API keys are present at runtime
  const envCheck = checkScannerEnvVars();
  console.log('Scanner env var check:', JSON.stringify(envCheck));

  const entries = Object.entries(scanners);

  const results = await Promise.allSettled(
    entries.map(([name, scanner]) => withTimeout(name, scanner, domain, options)),
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
