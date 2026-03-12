import type { ScannerResult } from './types';

/**
 * SecurityTrails scanner — stub.
 * Not configured for MVP. Returns empty findings without crashing.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function scanSecuritytrails(domain: string): Promise<ScannerResult> {
  console.log('SecurityTrails: not configured');
  return { module: 'securitytrails', success: true, findings: [] };
}
