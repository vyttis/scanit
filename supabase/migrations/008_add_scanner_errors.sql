-- Add scanner_errors JSONB column to scans table
-- Tracks which scanner modules failed and why, for UI visibility
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scanner_errors jsonb DEFAULT NULL;

COMMENT ON COLUMN scans.scanner_errors IS 'Array of {module, error} objects tracking scanner failures for this scan';
