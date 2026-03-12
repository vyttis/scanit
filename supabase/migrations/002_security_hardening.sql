-- Session 6: Security hardening
-- Verify RLS is enabled on all tables and add extra protections

-- ============================================================
-- RLS verification query (run manually to confirm):
-- SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';
-- Expected: all 6 tables show rowsecurity = true
-- ============================================================

-- Ensure audit_log is truly immutable: revoke UPDATE and DELETE
-- from all roles except postgres (superuser)
REVOKE UPDATE, DELETE ON audit_log FROM authenticated;
REVOKE UPDATE, DELETE ON audit_log FROM anon;
REVOKE UPDATE, DELETE ON audit_log FROM service_role;

-- Re-grant INSERT for service_role only (server-side audit writes)
GRANT INSERT ON audit_log TO service_role;

-- Ensure service_role can write findings, reports, scans (server-side operations)
-- but regular authenticated users cannot INSERT/UPDATE/DELETE on findings/reports directly
REVOKE INSERT, UPDATE, DELETE ON findings FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON reports FROM authenticated;

-- Verify storage bucket is private (must be done in Supabase dashboard):
-- Storage > reports bucket > Access: Private (no public URLs)
