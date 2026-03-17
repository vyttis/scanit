export type OrganizationSector =
  | 'energetika'
  | 'transportas'
  | 'sveikatos_apsauga'
  | 'skaitmenine_infrastruktura'
  | 'it_paslaugos'
  | 'viesasis_administravimas'
  | 'vandentiekis'
  | 'bankininkiste'
  | 'maisto_pramone'
  | 'gamyba'
  | 'moksliniai_tyrimai'
  | 'pasto_paslaugos'
  | 'atlieku_tvarkymas';

export type UserRole = 'admin' | 'viewer' | 'superadmin';
export type ScanType = 'light' | 'deep';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';
export type ScanModule = 'shodan' | 'hibp' | 'ssl' | 'mxtoolbox' | 'securitytrails' | 'virustotal' | 'abuseipdb' | 'urlscan';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Organization {
  id: string;
  name: string;
  domain: string;
  verified: boolean;
  verification_token: string | null;
  contact_email: string;
  sector: OrganizationSector | null;
  plan: PlanType;
  created_at: string;
}

export interface Profile {
  id: string;
  org_id: string | null;
  role: UserRole;
  created_at: string;
}

export interface ScannerError {
  module: string;
  error: string;
}

export interface Scan {
  id: string;
  org_id: string;
  scan_type: ScanType;
  status: ScanStatus;
  triggered_by: string | null;
  started_at: string | null;
  completed_at: string | null;
  scanner_errors: ScannerError[] | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  org_id: string;
  module: ScanModule;
  severity: FindingSeverity;
  title_lt: string;
  description_lt: string;
  recommendation_lt: string;
  nis2_article: string | null;
  evidence: Record<string, unknown> | null;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  org_id: string;
  pdf_path: string | null;
  risk_score: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
}

export interface AuditLogEntry {
  id: string;
  org_id: string | null;
  user_id: string | null;
  action: string;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}

export type PlanType = 'free' | 'basic' | 'professional';

export type FindingStatusType = 'open' | 'in_progress' | 'resolved' | 'accepted_risk' | 'false_positive';

export interface FindingStatus {
  id: string;
  finding_id: string;
  org_id: string;
  status: FindingStatusType;
  note: string | null;
  updated_by: string | null;
  updated_at: string;
  created_at: string;
}

export interface PublicScan {
  id: string;
  domain: string;
  email: string | null;
  ip_address: string | null;
  status: 'queued' | 'running' | 'completed' | 'failed';
  results: PublicScanResults | null;
  risk_score: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
}

export interface PublicScanFinding {
  module: ScanModule;
  severity: FindingSeverity;
  title_lt: string;
}

export interface PublicScanResults {
  findings: PublicScanFinding[];
  modules_run: string[];
}
