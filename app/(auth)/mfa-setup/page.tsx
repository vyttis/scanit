'use client';

import { useState, useEffect } from 'react';
import { createClient } from '@/lib/supabase/client';
import { useRouter } from 'next/navigation';

export default function MfaSetupPage() {
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [factorId, setFactorId] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  useEffect(() => {
    async function enrollMFA() {
      const { data, error } = await supabase.auth.mfa.enroll({
        factorType: 'totp',
        friendlyName: 'scanit.lt',
      });

      if (error) {
        setError('Klaida nustatant kelių veiksnių autentifikavimą.');
        return;
      }

      setQrCode(data.totp.qr_code);
      setSecret(data.totp.secret);
      setFactorId(data.id);
    }

    enrollMFA();
  }, [supabase.auth.mfa]);

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    if (!factorId) return;
    setLoading(true);
    setError(null);

    const { data: challengeData, error: challengeError } =
      await supabase.auth.mfa.challenge({ factorId });

    if (challengeError) {
      setError('Klaida kuriant tikrinimo užklausą.');
      setLoading(false);
      return;
    }

    const { error: verifyError } = await supabase.auth.mfa.verify({
      factorId,
      challengeId: challengeData.id,
      code: verifyCode,
    });

    if (verifyError) {
      setError('Neteisingas kodas. Bandykite dar kartą.');
      setLoading(false);
      return;
    }

    router.push('/dashboard');
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-md">
        <div>
          <h1 className="text-2xl font-bold text-center text-gray-900">
            Kelių veiksnių autentifikavimas
          </h1>
          <p className="mt-2 text-center text-sm text-gray-600">
            Pagal KSĮ reikalavimus, kelių veiksnių autentifikavimas yra privalomas.
            Nuskaitykite QR kodą naudodami autentifikavimo programėlę
            (pvz., Google Authenticator, Authy).
          </p>
        </div>

        {qrCode && (
          <div className="flex flex-col items-center space-y-4">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={qrCode} alt="MFA QR kodas" className="w-48 h-48" />
            {secret && (
              <div className="text-center">
                <p className="text-xs text-gray-500">
                  Jei negalite nuskaityti QR kodo, įveskite šį kodą rankiniu būdu:
                </p>
                <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded mt-1 block">
                  {secret}
                </code>
              </div>
            )}
          </div>
        )}

        <form onSubmit={handleVerify} className="space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm" role="alert">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="code" className="block text-sm font-medium text-gray-700">
              Patvirtinimo kodas
            </label>
            <input
              id="code"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ''))}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm text-center tracking-widest text-lg"
              placeholder="000000"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !factorId}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Tikrinama...' : 'Patvirtinti ir tęsti'}
          </button>
        </form>
      </div>
    </div>
  );
}
