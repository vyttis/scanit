const LT_TIMEZONE = 'Europe/Vilnius';

/**
 * Format a date as Lithuanian full datetime (e.g., "2026-03-13 14:30:00").
 */
export function formatLithuanianDateTime(date: string | Date): string {
  return new Date(date).toLocaleString('lt-LT', {
    timeZone: LT_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Format a date as Lithuanian date only (e.g., "2026-03-13").
 */
export function formatLithuanianDate(date: string | Date): string {
  return new Date(date).toLocaleDateString('lt-LT', {
    timeZone: LT_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });
}

/**
 * Format a date with long month name (e.g., "2026 m. kovo 13 d.").
 */
export function formatLithuanianDateLong(date: string | Date): string {
  return new Date(date).toLocaleDateString('lt-LT', {
    timeZone: LT_TIMEZONE,
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

/**
 * Format time only (e.g., "14:30").
 */
export function formatLithuanianTime(date: string | Date): string {
  return new Date(date).toLocaleTimeString('lt-LT', {
    timeZone: LT_TIMEZONE,
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format a date with short month (e.g., "kov. 13").
 * Useful for chart axis labels.
 */
export function formatLithuanianDateShort(date: string | Date): string {
  return new Date(date).toLocaleDateString('lt-LT', {
    timeZone: LT_TIMEZONE,
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Format for report: "YYYY-MM-DD" in Lithuanian timezone.
 */
export function formatReportDate(date: string | Date): string {
  const d = new Date(date);
  const parts = new Intl.DateTimeFormat('lt-LT', {
    timeZone: LT_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(d);
  const year = parts.find(p => p.type === 'year')?.value;
  const month = parts.find(p => p.type === 'month')?.value;
  const day = parts.find(p => p.type === 'day')?.value;
  return `${year}-${month}-${day}`;
}

/**
 * Format a date with long month name + time (e.g., "2026 m. kovo 13 d. 14:30").
 */
export function formatLithuanianDateTimeLong(date: string | Date): string {
  return new Date(date).toLocaleDateString('lt-LT', {
    timeZone: LT_TIMEZONE,
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  } as Intl.DateTimeFormatOptions);
}
