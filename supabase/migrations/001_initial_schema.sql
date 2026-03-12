-- pentester.lt — Initial database schema
-- All tables with Row Level Security (RLS) enabled from the start

-- ============================================================
-- 1. Organizations (clients)
-- ============================================================
CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  domain text NOT NULL UNIQUE,
  verified boolean DEFAULT false,
  verification_token text,
  contact_email text NOT NULL,
  sector text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 2. Profiles (users linked to auth.users)
-- ============================================================
CREATE TABLE profiles (
  id uuid PRIMARY KEY REFERENCES auth.users ON DELETE CASCADE,
  org_id uuid REFERENCES organizations ON DELETE SET NULL,
  role text NOT NULL CHECK (role IN ('admin', 'viewer')) DEFAULT 'viewer',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 3. Scans
-- ============================================================
CREATE TABLE scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
  scan_type text NOT NULL CHECK (scan_type IN ('light', 'deep')) DEFAULT 'light',
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')) DEFAULT 'queued',
  triggered_by uuid REFERENCES profiles,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 4. Findings
-- ============================================================
CREATE TABLE findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans ON DELETE CASCADE,
  org_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
  module text NOT NULL CHECK (module IN ('shodan', 'hibp', 'ssl', 'mxtoolbox', 'securitytrails', 'virustotal', 'abuseipdb', 'urlscan')),
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title_lt text NOT NULL,
  description_lt text NOT NULL,
  recommendation_lt text NOT NULL,
  nis2_article text,
  evidence jsonb,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 5. Reports
-- ============================================================
CREATE TABLE reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans ON DELETE CASCADE,
  org_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
  pdf_path text,
  risk_score integer CHECK (risk_score BETWEEN 0 AND 100),
  critical_count integer DEFAULT 0,
  high_count integer DEFAULT 0,
  medium_count integer DEFAULT 0,
  low_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 6. Audit log (immutable — no UPDATE or DELETE policies)
-- ============================================================
CREATE TABLE audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid REFERENCES organizations ON DELETE SET NULL,
  user_id uuid REFERENCES profiles ON DELETE SET NULL,
  action text NOT NULL,
  details jsonb,
  ip_address text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- RLS Policies
-- ============================================================

-- Helper: get current user's org_id
-- Used in all RLS policies for org isolation

-- Organizations: users can only see their own org
CREATE POLICY "org_isolation_select" ON organizations
  FOR SELECT USING (
    id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

-- Organizations: only admins can update their org
CREATE POLICY "org_isolation_update" ON organizations
  FOR UPDATE USING (
    id = (SELECT org_id FROM profiles WHERE id = auth.uid())
    AND EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin')
  );

-- Profiles: users can see profiles in their own org
CREATE POLICY "org_isolation_select" ON profiles
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

-- Profiles: users can update their own profile
CREATE POLICY "self_update" ON profiles
  FOR UPDATE USING (id = auth.uid());

-- Profiles: allow insert for new user registration
CREATE POLICY "self_insert" ON profiles
  FOR INSERT WITH CHECK (id = auth.uid());

-- Scans: org isolation
CREATE POLICY "org_isolation_select" ON scans
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

CREATE POLICY "org_isolation_insert" ON scans
  FOR INSERT WITH CHECK (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
    AND EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin')
  );

-- Findings: org isolation (read-only for users, server writes)
CREATE POLICY "org_isolation_select" ON findings
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

-- Reports: org isolation (read-only for users, server writes)
CREATE POLICY "org_isolation_select" ON reports
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

-- Audit log: org members can read their own org's logs, INSERT only via service role
CREATE POLICY "org_isolation_select" ON audit_log
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

-- No UPDATE or DELETE policies on audit_log — logs are immutable

-- ============================================================
-- Indexes for performance
-- ============================================================
CREATE INDEX idx_profiles_org_id ON profiles(org_id);
CREATE INDEX idx_scans_org_id ON scans(org_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_org_id ON findings(org_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_reports_org_id ON reports(org_id);
CREATE INDEX idx_reports_scan_id ON reports(scan_id);
CREATE INDEX idx_audit_log_org_id ON audit_log(org_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

-- ============================================================
-- Function: auto-create profile on user signup
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (id, role)
  VALUES (NEW.id, 'admin');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
