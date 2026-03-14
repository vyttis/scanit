'use client';

import { createClient } from '@/lib/supabase/client';
import { useRouter } from 'next/navigation';

export function LogoutButton() {
  const supabase = createClient();
  const router = useRouter();

  async function handleLogout() {
    // Audit log the logout before signing out
    try {
      await fetch('/api/auth/audit-logout', { method: 'POST' });
    } catch {
      // Don't block logout if audit fails
    }
    await supabase.auth.signOut();
    router.push('/login');
  }

  return (
    <button
      onClick={handleLogout}
      className="text-sm text-gray-600 hover:text-gray-900"
      aria-label="Atsijungti nuo platformos"
    >
      Atsijungti
    </button>
  );
}
