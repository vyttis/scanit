import type { ScannerResult } from './types';

/**
 * SecurityTrails scanner — stub.
 * Not configured for MVP. Returns empty findings without crashing.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function scanSecuritytrails(_domain: string): Promise<ScannerResult> {
  return { module: 'securitytrails', success: true, findings: [] };
}
