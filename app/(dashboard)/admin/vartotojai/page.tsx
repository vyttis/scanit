import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import { AdminUsersClient } from './client';

export default async function AdminUsersPage() {
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

  // Get pending users with their org info
  const { data: pendingUsers } = await serviceClient
    .from('profiles')
    .select(`
      id,
      first_name,
      last_name,
      status,
      created_at,
      org_id,
      organizations (
        id,
        name,
        domain
      )
    `)
    .in('status', ['pending', 'approved', 'rejected'])
    .order('created_at', { ascending: false });

  // Get emails from auth.users
  const { data: authUsers } = await serviceClient.auth.admin.listUsers();
  const emailMap = new Map(
    authUsers?.users?.map(u => [u.id, u.email]) || []
  );

  const users = (pendingUsers || []).map(u => {
    // Supabase returns joined data; handle both single object and array cases
    const org = u.organizations as unknown as { id: string; name: string; domain: string } | null;
    return {
      id: u.id,
      firstName: u.first_name || '',
      lastName: u.last_name || '',
      email: emailMap.get(u.id) || '',
      status: u.status as string,
      createdAt: u.created_at,
      organizationName: org?.name || '',
      organizationDomain: org?.domain || '',
    };
  });

  return <AdminUsersClient users={users} />;
}
