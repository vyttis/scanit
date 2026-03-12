-- Add missing created_at indexes for performance on common ORDER BY queries
-- (scans, findings, and reports are frequently queried with ORDER BY created_at)

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings (created_at);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports (created_at DESC);
