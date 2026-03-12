import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import { AdminAuditClient } from './client';

export default async function AdminAuditPage() {
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

  // Fetch last 200 audit log entries across ALL organizations
  const { data: auditLogs } = await serviceClient
    .from('audit_log')
    .select(`
      id,
      org_id,
      user_id,
      action,
      details,
      ip_address,
      created_at
    `)
    .order('created_at', { ascending: false })
    .limit(200);

  // Fetch all organization names for display
  const { data: organizations } = await serviceClient
    .from('organizations')
    .select('id, name');

  const orgMap = new Map(
    (organizations || []).map(o => [o.id, o.name])
  );

  // Fetch user emails from auth.users
  const { data: authUsers } = await serviceClient.auth.admin.listUsers();
  const emailMap = new Map(
    authUsers?.users?.map(u => [u.id, u.email]) || []
  );

  const entries = (auditLogs || []).map(log => ({
    id: log.id,
    action: log.action,
    details: log.details,
    ipAddress: log.ip_address || '',
    createdAt: log.created_at,
    userEmail: emailMap.get(log.user_id) || '',
    organizationName: orgMap.get(log.org_id) || '',
  }));

  return <AdminAuditClient entries={entries} />;
}
