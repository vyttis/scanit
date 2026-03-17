import type { FindingSeverity } from '@/types/database';

/**
 * Default SLA deadlines by severity (in days).
 */
export const SLA_DAYS: Record<string, number> = {
  critical: 7,
  high: 30,
  medium: 90,
  low: 180,
  info: 0, // no SLA for info
};

export interface SlaStatus {
  deadlineDays: number;
  elapsedDays: number;
  remainingDays: number;
  isOverdue: boolean;
  isExpiringSoon: boolean; // within 3 days
}

/**
 * Calculate SLA status for a finding based on its severity and creation date.
 */
export function calculateSla(
  severity: FindingSeverity,
  createdAt: string | Date,
): SlaStatus | null {
  const deadlineDays = SLA_DAYS[severity];
  if (!deadlineDays) return null; // no SLA for info

  const created = new Date(createdAt);
  const now = new Date();
  const elapsedMs = now.getTime() - created.getTime();
  const elapsedDays = Math.floor(elapsedMs / (1000 * 60 * 60 * 24));
  const remainingDays = deadlineDays - elapsedDays;

  return {
    deadlineDays,
    elapsedDays,
    remainingDays,
    isOverdue: remainingDays < 0,
    isExpiringSoon: remainingDays >= 0 && remainingDays <= 3,
  };
}

/**
 * Format SLA remaining time as human-readable Lithuanian text.
 */
export function formatSlaText(sla: SlaStatus): string {
  if (sla.isOverdue) {
    const overdueDays = Math.abs(sla.remainingDays);
    return `Vėluojama ${overdueDays} d.`;
  }
  if (sla.remainingDays === 0) {
    return 'Šiandien terminas';
  }
  return `Liko ${sla.remainingDays} d.`;
}

/**
 * Count overdue findings from a list with SLA information.
 */
export function countOverdue(
  findings: Array<{ severity: FindingSeverity; created_at: string; status?: string }>,
): { overdue: number; expiringSoon: number } {
  let overdue = 0;
  let expiringSoon = 0;

  for (const f of findings) {
    if (f.status && f.status !== 'open' && f.status !== 'in_progress') continue;
    const sla = calculateSla(f.severity, f.created_at);
    if (!sla) continue;
    if (sla.isOverdue) overdue++;
    else if (sla.isExpiringSoon) expiringSoon++;
  }

  return { overdue, expiringSoon };
}
