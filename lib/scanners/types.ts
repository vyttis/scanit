import type { ScanModule, FindingSeverity } from '@/types/database';

/**
 * Raw finding output from a scanner module.
 * Does not include scan_id or org_id — those are added by the orchestrator.
 */
export interface ScannerFinding {
  module: ScanModule;
  severity: FindingSeverity;
  title_lt: string;
  description_lt: string;
  recommendation_lt: string;
  nis2_article: string | null;
  evidence: Record<string, unknown>;
}

/**
 * Result returned by each scanner module.
 */
export interface ScannerResult {
  module: ScanModule;
  success: boolean;
  findings: ScannerFinding[];
  error?: string;
}

/** Optional extra parameters for scanners (professional plan). */
export interface ScannerOptions {
  ipRanges?: string[];
  subdomains?: string[];
  emails?: string[];
}

/**
 * Scanner function signature — every module exports this.
 */
export type ScannerFunction = (domain: string, options?: ScannerOptions) => Promise<ScannerResult>;

/**
 * Expand CIDR ranges into individual IP addresses, capped at maxTotal.
 * Supports /24 through /32. Returns an empty array for invalid input.
 */
export function expandCidrToIps(cidrs: string[], maxTotal = 20): string[] {
  const ips: string[] = [];
  for (const cidr of cidrs) {
    if (ips.length >= maxTotal) break;
    const parts = cidr.split('/');
    if (parts.length !== 2) continue;
    const octets = parts[0].split('.').map(Number);
    const prefix = parseInt(parts[1], 10);
    if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255)) continue;
    if (isNaN(prefix) || prefix < 24 || prefix > 32) continue; // cap at /24 (256 IPs max)

    const baseIp = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    const hostBits = 32 - prefix;
    const count = 1 << hostBits;

    for (let i = 0; i < count && ips.length < maxTotal; i++) {
      const ip = baseIp + i;
      ips.push(`${(ip >>> 24) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 8) & 0xff}.${ip & 0xff}`);
    }
  }
  return ips;
}

/**
 * Deduplicate an array of IP addresses.
 */
export function deduplicateIps(ips: string[]): string[] {
  return Array.from(new Set(ips));
}

/**
 * Fetch with a timeout (default 10 seconds per CLAUDE.md §7).
 * Wraps native fetch with AbortController.
 */
export function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 10_000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}
