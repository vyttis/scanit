'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Klaida. Bandykite dar kartą.');
        setLoading(false);
        return;
      }

      setSuccess(true);
    } catch {
      setError('Tinklo klaida. Bandykite dar kartą.');
    }

    setLoading(false);
  }

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-md">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-gray-900">scanit.lt</h1>
            <p className="mt-4 text-gray-600 text-sm">
              Jei el. pašto adresas <strong>{email}</strong> yra registruotas mūsų sistemoje,
              išsiuntėme nuorodą slaptažodžio keitimui. Patikrinkite savo el. paštą.
            </p>
            <Link
              href="/login"
              className="mt-6 inline-block text-blue-600 hover:text-blue-500 font-medium text-sm"
            >
              Grįžti į prisijungimą
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-md">
        <div>
          <h1 className="text-2xl font-bold text-center text-gray-900">scanit.lt</h1>
          <h2 className="mt-2 text-center text-lg text-gray-600">
            Slaptažodžio atkūrimas
          </h2>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

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

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Siunčiama...' : 'Siųsti nuorodą'}
          </button>

          <p className="text-center text-sm text-gray-600">
            <Link href="/login" className="text-blue-600 hover:text-blue-500 font-medium">
              Grįžti į prisijungimą
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
