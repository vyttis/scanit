import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import { AdminOrganizationsClient } from './client';

export default async function AdminOrganizationsPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    redirect('/login');
  }

  // Check superadmin role
  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  if (profile?.role !== 'superadmin') {
    redirect('/dashboard');
  }

  // Fetch all organizations
  const { data: organizations } = await serviceClient
    .from('organizations')
    .select('*')
    .order('created_at', { ascending: false });

  // Fetch scan counts per organization
  const { data: scanCounts } = await serviceClient
    .from('scans')
    .select('org_id');

  // Fetch latest completed reports with risk scores per organization
  const { data: latestReports } = await serviceClient
    .from('reports')
    .select('org_id, risk_score, created_at')
    .order('created_at', { ascending: false });

  // Fetch total findings per organization
  const { data: allFindings } = await serviceClient
    .from('findings')
    .select('org_id');

  // Fetch latest completed scan dates per organization
  const { data: latestScans } = await serviceClient
    .from('scans')
    .select('org_id, completed_at')
    .eq('status', 'completed')
    .order('completed_at', { ascending: false });

  // Build scan count map
  const scanCountMap = new Map<string, number>();
  (scanCounts || []).forEach(s => {
    scanCountMap.set(s.org_id, (scanCountMap.get(s.org_id) || 0) + 1);
  });

  // Build latest risk score map (first occurrence per org_id is the latest)
  const riskScoreMap = new Map<string, number | null>();
  (latestReports || []).forEach(r => {
    if (!riskScoreMap.has(r.org_id)) {
      riskScoreMap.set(r.org_id, r.risk_score);
    }
  });

  // Build findings count map
  const findingsCountMap = new Map<string, number>();
  (allFindings || []).forEach(f => {
    findingsCountMap.set(f.org_id, (findingsCountMap.get(f.org_id) || 0) + 1);
  });

  // Build latest scan date map
  const lastScanDateMap = new Map<string, string | null>();
  (latestScans || []).forEach(s => {
    if (!lastScanDateMap.has(s.org_id)) {
      lastScanDateMap.set(s.org_id, s.completed_at);
    }
  });

  // Build plan map from organizations data (plan column is on organizations table)
  const planMap = new Map<string, string>();
  (organizations || []).forEach(org => {
    planMap.set(org.id, org.plan || 'basic');
  });

  const orgs = (organizations || []).map(org => ({
    id: org.id,
    name: org.name,
    domain: org.domain,
    verified: org.verified ?? false,
    contactEmail: org.contact_email,
    sector: org.sector || null,
    createdAt: org.created_at,
    scanCount: scanCountMap.get(org.id) || 0,
    latestRiskScore: riskScoreMap.get(org.id) ?? null,
    totalFindings: findingsCountMap.get(org.id) || 0,
    lastScanDate: lastScanDateMap.get(org.id) ?? null,
    plan: planMap.get(org.id) || 'basic',
  }));

  return <AdminOrganizationsClient organizations={orgs} />;
}
