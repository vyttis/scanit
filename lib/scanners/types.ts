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

/**
 * Scanner function signature — every module exports this.
 */
export type ScannerFunction = (domain: string) => Promise<ScannerResult>;
