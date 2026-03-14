'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function TikrintiPage() {
  const router = useRouter();
  const [domain, setDomain] = useState('');
  const [email, setEmail] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function sanitizeDomain(input: string): string {
    return input
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/.*$/, '');
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!consent) {
      setError('Turite patvirtinti, kad turite teisę atlikti šio domeno patikrą.');
      return;
    }

    const cleanDomain = sanitizeDomain(domain);
    if (!cleanDomain) {
      setError('Įveskite domeno pavadinimą.');
      return;
    }

    setLoading(true);

    try {
      const res = await fetch('/api/public-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: cleanDomain,
          email: email.trim() || undefined,
          consent: true,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Klaida. Bandykite dar kartą.');
        setLoading(false);
        return;
      }

      // Redirect to results page
      router.push(`/rezultatai/${data.id}`);
    } catch {
      setError('Tinklo klaida. Bandykite dar kartą.');
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 flex flex-col">
      {/* Header */}
      <header className="py-6 px-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <a href="/tikrinti" className="text-2xl font-bold text-white">
            scanit.lt
          </a>
          <a
            href="/login"
            className="text-sm text-slate-300 hover:text-white transition-colors"
          >
            Prisijungti
          </a>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 flex items-center justify-center px-4 pb-16">
        <div className="max-w-xl w-full">
          <div className="text-center mb-10">
            <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
              Patikrinkite savo domeno saugumą
            </h1>
            <p className="text-lg text-slate-300">
              Nemokamas išorinio atakos paviršiaus skenavimas.
              Rezultatai per 60 sekundžių.
            </p>
          </div>

          <form
            onSubmit={handleSubmit}
            className="bg-white rounded-xl shadow-2xl p-6 sm:p-8 space-y-5"
          >
            {error && (
              <div
                className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm"
                role="alert"
              >
                {error}
              </div>
            )}

            {/* Domain input */}
            <div>
              <label
                htmlFor="domain"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Domeno pavadinimas
              </label>
              <input
                id="domain"
                type="text"
                required
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-base"
                placeholder="organizacija.lt"
                disabled={loading}
              />
            </div>

            {/* Email input (optional) */}
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Įveskite el. paštą rezultatams gauti{' '}
                <span className="text-gray-400 font-normal">(neprivaloma)</span>
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-base"
                placeholder="vardas@organizacija.lt"
                disabled={loading}
              />
            </div>

            {/* Consent checkbox */}
            <div className="flex items-start gap-3">
              <input
                id="consent"
                type="checkbox"
                checked={consent}
                onChange={(e) => setConsent(e.target.checked)}
                className="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                disabled={loading}
              />
              <label htmlFor="consent" className="text-sm text-gray-600 leading-snug">
                Patvirtinu, kad turiu teisę atlikti šio domeno patikrą arba atlieku ją
                savo organizacijos domeno vardu. Suprantu, kad scanit.lt naudoja tik
                viešai prieinamą informaciją.
              </label>
            </div>

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading || !consent}
              className="w-full py-3 px-6 bg-blue-600 text-white font-semibold rounded-lg shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-base"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg
                    className="animate-spin h-5 w-5"
                    viewBox="0 0 24 24"
                    fill="none"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                  Skenuojama...
                </span>
              ) : (
                'Skenuoti dabar'
              )}
            </button>

            <p className="text-xs text-gray-400 text-center">
              Nemokamas skenavimas — iki 4 patikrų per dieną. Naudojame tik viešai
              prieinamą informaciją.
            </p>
          </form>

          {/* Features list */}
          <div className="mt-10 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
            {[
              { label: 'Atidaryti prievadai', icon: '🔓' },
              { label: 'SSL sertifikatai', icon: '🔒' },
              { label: 'El. pašto apsauga', icon: '📧' },
              { label: 'Reputacija', icon: '🛡' },
            ].map((item) => (
              <div key={item.label} className="text-slate-300">
                <div className="text-2xl mb-1">{item.icon}</div>
                <div className="text-sm">{item.label}</div>
              </div>
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 px-4 text-center text-slate-500 text-sm">
        scanit.lt — Kibernetinio saugumo platforma pagal KSĮ ir NIS2 reikalavimus
      </footer>
    </div>
  );
}
