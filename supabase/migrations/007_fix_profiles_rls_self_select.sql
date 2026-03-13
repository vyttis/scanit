-- Migration 007: Fix profiles RLS — allow users to read their own profile
-- The current policy uses org_id comparison which fails for superadmin (org_id IS NULL)
-- because NULL = NULL is FALSE in SQL.

-- Drop the existing select policy
DROP POLICY IF EXISTS "org_isolation_select" ON profiles;

-- New policy: users can always read their own profile,
-- AND profiles in their own org
CREATE POLICY "profiles_select" ON profiles
  FOR SELECT USING (
    id = auth.uid()
    OR org_id = (SELECT org_id FROM profiles WHERE id = auth.uid())
  );
