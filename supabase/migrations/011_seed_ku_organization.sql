-- Migration 011: Seed VšĮ Klaipėdos universitetas as pilot organization
--
-- Migration 009 tried to link the superadmin to KU, but the organization
-- row was never created. This migration creates it and re-links the superadmin.

-- 1. Create the KU organization if it doesn't exist
INSERT INTO organizations (name, domain, verified, contact_email, sector, plan)
VALUES (
  'VšĮ Klaipėdos universitetas',
  'ku.lt',
  true,                          -- verified (pilot customer, bypass DNS check)
  'vytis.radvila@ku.lt',
  'moksliniai_tyrimai',          -- Research sector
  'professional'                 -- Professional plan for client zero
)
ON CONFLICT (domain) DO NOTHING;

-- 2. Link superadmin profile to KU organization
UPDATE profiles
SET org_id = (SELECT id FROM organizations WHERE domain = 'ku.lt')
WHERE role = 'superadmin'
  AND (org_id IS NULL OR org_id IS DISTINCT FROM (SELECT id FROM organizations WHERE domain = 'ku.lt'));
