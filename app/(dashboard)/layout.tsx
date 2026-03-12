import { createServerSupabaseClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { LogoutButton } from '@/components/logout-button';
import { NavLink } from '@/components/nav-link';

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    redirect('/login');
  }

  // Check MFA status — enforce MFA for all users
  const { data: factors } = await supabase.auth.mfa.listFactors();
  const totp = factors?.totp ?? [];
  const hasVerifiedFactor = totp.some((f) => f.status === 'verified');

  if (!hasVerifiedFactor) {
    redirect('/mfa-setup');
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('org_id, role, status')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link href="/dashboard" className="text-xl font-bold text-gray-900">
                scanit.lt
              </Link>
              <NavLink href="/dashboard">
                Valdymo skydelis
              </NavLink>
              <NavLink href="/scans">
                Skenavimai
              </NavLink>
              <NavLink href="/reports">
                Ataskaitos
              </NavLink>
              <NavLink href="/settings">
                Nustatymai
              </NavLink>
              {isSuperadmin && (
                <NavLink
                  href="/admin/vartotojai"
                  className="text-sm text-purple-600 hover:text-purple-900 font-medium"
                >
                  Vartotojai
                </NavLink>
              )}
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-500">{user.email}</span>
              {profile?.role && (
                <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                  {profile.role === 'superadmin' ? 'Superadminas' : profile.role === 'admin' ? 'Administratorius' : 'Stebėtojas'}
                </span>
              )}
              <LogoutButton />
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  );
}
