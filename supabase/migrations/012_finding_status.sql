-- Migration 012: Finding status tracking (remediation lifecycle)
--
-- Allows users to track the status of each finding:
-- open → in_progress → resolved / accepted_risk / false_positive
-- This is critical for CISOs to demonstrate compliance progress to auditors.

CREATE TABLE IF NOT EXISTS finding_status (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id uuid NOT NULL REFERENCES findings ON DELETE CASCADE,
  org_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')),
  note text,
  updated_by uuid REFERENCES profiles ON DELETE SET NULL,
  updated_at timestamptz DEFAULT now(),
  created_at timestamptz DEFAULT now()
);

-- One status per finding
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_status_finding ON finding_status (finding_id);

-- Org-based lookup
CREATE INDEX IF NOT EXISTS idx_finding_status_org ON finding_status (org_id);

-- Status-based filtering
CREATE INDEX IF NOT EXISTS idx_finding_status_status ON finding_status (status);

-- Enable RLS
ALTER TABLE finding_status ENABLE ROW LEVEL SECURITY;

-- RLS policies: org isolation (matching existing pattern)
CREATE POLICY "org_isolation_select" ON finding_status
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );

CREATE POLICY "org_isolation_insert" ON finding_status
  FOR INSERT WITH CHECK (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
    AND EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('admin', 'superadmin'))
  );

CREATE POLICY "org_isolation_update" ON finding_status
  FOR UPDATE USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
    AND EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('admin', 'superadmin'))
  );

-- No delete — status history should be preserved
REVOKE DELETE ON finding_status FROM authenticated;
