-- Migration 005: Public scans table + organization data enrichment fields
-- Progressive data model: free scan without registration, paid enrichment

-- Public scans table — no RLS needed, public data
CREATE TABLE IF NOT EXISTS public_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain text NOT NULL,
  email text,
  ip_address text,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  results jsonb,
  risk_score integer CHECK (risk_score BETWEEN 0 AND 100),
  critical_count integer DEFAULT 0,
  high_count integer DEFAULT 0,
  medium_count integer DEFAULT 0,
  low_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_public_scans_domain ON public_scans (domain);
CREATE INDEX IF NOT EXISTS idx_public_scans_created_at ON public_scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_public_scans_ip_address ON public_scans (ip_address);

-- Organization enrichment: IP ranges, email lists, subdomains
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ip_ranges text[] DEFAULT '{}';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS employee_emails text[] DEFAULT '{}';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subdomains text[] DEFAULT '{}';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS plan text DEFAULT 'pagrindinis' CHECK (plan IN ('pagrindinis', 'profesionalus'));
