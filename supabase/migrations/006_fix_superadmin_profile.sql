-- Migration 006: Fix superadmin profile
-- The superadmin (vytis.radvila@ku.lt) may have been created via normal registration
-- with role='admin' and status='pending'. This fixes that.

-- Update the superadmin profile to have correct role and status
-- This uses a subquery to find the auth.users ID by email
UPDATE profiles
SET role = 'superadmin', status = 'approved'
WHERE id IN (
  SELECT id FROM auth.users WHERE email = 'vytis.radvila@ku.lt'
);

-- Also ensure the handle_new_user trigger sets superadmin role for the configured email
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
DECLARE
  v_superadmin_email text;
BEGIN
  -- Check if this is the superadmin email (set via app config)
  -- For now, hardcode the known superadmin email
  v_superadmin_email := 'vytis.radvila@ku.lt';

  IF NEW.email = v_superadmin_email THEN
    INSERT INTO public.profiles (id, role, status)
    VALUES (NEW.id, 'superadmin', 'approved');
  ELSE
    INSERT INTO public.profiles (id, role, status)
    VALUES (NEW.id, 'admin', 'pending');
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
