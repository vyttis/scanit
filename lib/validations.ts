/**
 * Domain validation — only allows valid domain format
 * No user input ever passed directly to API calls without sanitization
 */
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  return DOMAIN_REGEX.test(domain);
}

export function sanitizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  return EMAIL_REGEX.test(email);
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidUuid(value: string): boolean {
  return UUID_REGEX.test(value);
}

const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

export function isValidCidr(cidr: string): boolean {
  if (!CIDR_REGEX.test(cidr)) return false;
  const [ip, prefix] = cidr.split('/');
  const parts = ip.split('.').map(Number);
  const prefixNum = Number(prefix);
  return parts.every((p) => p >= 0 && p <= 255) && prefixNum >= 0 && prefixNum <= 32;
}

export function generateVerificationToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `scanit-lt-verify=${hex}`;
}
