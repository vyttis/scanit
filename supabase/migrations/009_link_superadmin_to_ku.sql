-- Link superadmin profile to VšĮ Klaipėdos universitetas organization
-- This ensures superadmin's dashboard shows KU data and superadmin can trigger
-- scans both from their own dashboard AND from /admin/organizacijos for any org.

UPDATE profiles
SET org_id = (SELECT id FROM organizations WHERE domain = 'ku.lt')
WHERE id = (SELECT id FROM profiles WHERE role = 'superadmin' LIMIT 1)
  AND org_id IS DISTINCT FROM (SELECT id FROM organizations WHERE domain = 'ku.lt');
