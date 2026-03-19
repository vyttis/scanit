-- Fix plan constraint: ensure 'free', 'basic', 'professional' are all allowed
-- This is a safety migration in case 010 didn't fully apply

ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_plan_check;

-- Update any legacy Lithuanian values
UPDATE organizations SET plan = 'basic' WHERE plan = 'pagrindinis';
UPDATE organizations SET plan = 'professional' WHERE plan = 'profesionalus';
UPDATE organizations SET plan = 'basic' WHERE plan IS NULL;

ALTER TABLE organizations ADD CONSTRAINT organizations_plan_check
  CHECK (plan IN ('free', 'basic', 'professional'));

ALTER TABLE organizations ALTER COLUMN plan SET DEFAULT 'basic';
ALTER TABLE organizations ALTER COLUMN plan SET NOT NULL;
