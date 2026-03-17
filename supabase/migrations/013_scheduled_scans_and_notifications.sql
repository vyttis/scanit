-- Migration 013: Scheduled scans + Notifications
--
-- Adds auto-scan scheduling columns to organizations
-- and creates a notifications table for in-app notification center.

-- ============================================================
-- Scheduled scans
-- ============================================================
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS auto_scan_enabled boolean DEFAULT false;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS auto_scan_day integer CHECK (auto_scan_day IS NULL OR (auto_scan_day BETWEEN 1 AND 28));

-- ============================================================
-- Notifications
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
  user_id uuid REFERENCES profiles ON DELETE CASCADE,  -- NULL = all org users
  type text NOT NULL,
  title_lt text NOT NULL,
  body_lt text,
  link text,            -- internal link (e.g., /scans/abc-123)
  read boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- Users can see notifications for their org (targeted to them or to all)
CREATE POLICY "org_isolation_select" ON notifications
  FOR SELECT USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
    AND (user_id IS NULL OR user_id = auth.uid())
  );

-- Only update read status (mark as read)
CREATE POLICY "org_isolation_update" ON notifications
  FOR UPDATE USING (
    org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
    AND (user_id IS NULL OR user_id = auth.uid())
  );

-- Insert only via service_role
REVOKE INSERT ON notifications FROM authenticated;
REVOKE DELETE ON notifications FROM authenticated;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_notifications_org_user ON notifications (org_id, user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications (org_id, read) WHERE NOT read;
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications (created_at DESC);
