import type { Finding } from '@/types/database';

export type DeltaCategory = 'new' | 'resolved' | 'persistent';

export interface DeltaFinding {
  finding: Finding;
  category: DeltaCategory;
}

export interface ScanDelta {
  newFindings: Finding[];
  resolvedFindings: Finding[];
  persistentFindings: Finding[];
  newCount: number;
  resolvedCount: number;
  persistentCount: number;
}

/**
 * Generate a fingerprint for a finding to compare across scans.
 * Uses module + title as the stable identifier (evidence changes between scans).
 */
function findingFingerprint(f: Pick<Finding, 'module' | 'title_lt'>): string {
  return `${f.module}::${f.title_lt.trim().toLowerCase()}`;
}

/**
 * Compare two sets of findings (current vs previous scan) and categorize them.
 *
 * - new: exists in current but not in previous
 * - resolved: existed in previous but not in current
 * - persistent: exists in both
 */
export function computeScanDelta(
  currentFindings: Finding[],
  previousFindings: Finding[],
): ScanDelta {
  const previousSet = new Map<string, Finding>();
  for (const f of previousFindings) {
    previousSet.set(findingFingerprint(f), f);
  }

  const currentSet = new Map<string, Finding>();
  for (const f of currentFindings) {
    currentSet.set(findingFingerprint(f), f);
  }

  const newFindings: Finding[] = [];
  const persistentFindings: Finding[] = [];

  currentSet.forEach((finding, fp) => {
    if (previousSet.has(fp)) {
      persistentFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  });

  const resolvedFindings: Finding[] = [];
  previousSet.forEach((finding, fp) => {
    if (!currentSet.has(fp)) {
      resolvedFindings.push(finding);
    }
  });

  return {
    newFindings,
    resolvedFindings,
    persistentFindings,
    newCount: newFindings.length,
    resolvedCount: resolvedFindings.length,
    persistentCount: persistentFindings.length,
  };
}
