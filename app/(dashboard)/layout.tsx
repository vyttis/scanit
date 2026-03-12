import { createServerSupabaseClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { LogoutButton } from '@/components/logout-button';

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
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link href="/dashboard" className="text-xl font-bold text-gray-900">
                scanit.lt
              </Link>
              <Link
                href="/dashboard"
                className="text-sm text-gray-600 hover:text-gray-900"
              >
                Valdymo skydelis
              </Link>
              <Link
                href="/scans"
                className="text-sm text-gray-600 hover:text-gray-900"
              >
                Skenavimai
              </Link>
              <Link
                href="/reports"
                className="text-sm text-gray-600 hover:text-gray-900"
              >
                Ataskaitos
              </Link>
              <Link
                href="/settings"
                className="text-sm text-gray-600 hover:text-gray-900"
              >
                Nustatymai
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-500">{user.email}</span>
              {profile?.role && (
                <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                  {profile.role === 'admin' ? 'Administratorius' : 'Stebėtojas'}
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
