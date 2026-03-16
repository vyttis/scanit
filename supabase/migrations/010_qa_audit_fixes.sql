-- Migration 010: QA Audit fixes
-- 1. Add 'suspended' to profiles status CHECK constraint
-- 2. Fix plan column values: use English names to match application code
-- 3. Remove hardcoded superadmin email from handle_new_user trigger

-- ============================================================
-- 1. Fix profiles status CHECK: add 'suspended'
-- ============================================================
ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_status_check;
ALTER TABLE profiles ADD CONSTRAINT profiles_status_check
  CHECK (status IN ('pending', 'approved', 'rejected', 'suspended'));

-- ============================================================
-- 2. Fix plan CHECK on organizations: use English values matching code
-- ============================================================
-- Drop old constraint (Lithuanian values)
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_plan_check;
-- Update any existing Lithuanian values to English
UPDATE organizations SET plan = 'basic' WHERE plan = 'pagrindinis';
UPDATE organizations SET plan = 'professional' WHERE plan = 'profesionalus';
-- Add new constraint with English values + 'free'
ALTER TABLE organizations ADD CONSTRAINT organizations_plan_check
  CHECK (plan IN ('free', 'basic', 'professional'));
-- Update default
ALTER TABLE organizations ALTER COLUMN plan SET DEFAULT 'basic';

-- ============================================================
-- 3. Remove hardcoded superadmin email from trigger
-- The superadmin should be set via application code, not DB trigger.
-- New users default to admin+pending (existing behavior for non-superadmin).
-- ============================================================
-- ============================================================
-- 4. Prevent concurrent scans via partial unique index
-- Only one queued/running scan per org at database level
-- ============================================================
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_one_active_per_org
  ON scans (org_id)
  WHERE status IN ('queued', 'running');

-- ============================================================
-- 5. Remove hardcoded superadmin email from trigger
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (id, role, status)
  VALUES (NEW.id, 'admin', 'pending');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
