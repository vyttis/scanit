'use client';

import { useState } from 'react';
import { createClient } from '@/lib/supabase/client';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const { data, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (authError) {
      setError('Neteisingi prisijungimo duomenys. Bandykite dar kartą.');
      setLoading(false);
      return;
    }

    // Check if MFA is required
    if (data.session && data.user) {
      const { data: factors } = await supabase.auth.mfa.listFactors();
      const totp = factors?.totp ?? [];

      if (totp.length === 0) {
        // No MFA set up — redirect to MFA setup
        router.push('/mfa-setup');
        return;
      }

      // MFA is set up — need to verify
      const factor = totp[0];
      const { data: challengeData, error: challengeError } =
        await supabase.auth.mfa.challenge({ factorId: factor.id });

      if (challengeError) {
        setError('Klaida tikrinant kelių veiksnių autentifikavimą.');
        setLoading(false);
        return;
      }

      // Store challenge ID and redirect to MFA verify page
      sessionStorage.setItem('mfa_challenge_id', challengeData.id);
      sessionStorage.setItem('mfa_factor_id', factor.id);
      router.push('/mfa-verify');
      return;
    }

    setLoading(false);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-md">
        <div>
          <h1 className="text-2xl font-bold text-center text-gray-900">
            scanit.lt
          </h1>
          <h2 className="mt-2 text-center text-lg text-gray-600">
            Prisijungimas prie platformos
          </h2>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleLogin}>
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                El. pašto adresas
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                placeholder="jusu@organizacija.lt"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Slaptažodis
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Jungiamasi...' : 'Prisijungti'}
          </button>

          <p className="text-center text-sm text-gray-600">
            Neturite paskyros?{' '}
            <Link href="/register" className="text-blue-600 hover:text-blue-500 font-medium">
              Registruotis
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
