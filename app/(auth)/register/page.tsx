'use client';

import { useState } from 'react';
import Link from 'next/link';

const BLOCKED_DOMAINS = [
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
  'mail.ru', 'inbox.lt', 'one.lt', 'yahoo.lt', 'live.com',
  'icloud.com', 'protonmail.com', 'yandex.ru',
];

function extractDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '');
}

export default function RegisterPage() {
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [orgName, setOrgName] = useState('');
  const [orgWebsite, setOrgWebsite] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  function validateDomains(): string | null {
    const emailDomain = email.split('@')[1]?.toLowerCase();
    const websiteDomain = extractDomain(orgWebsite);

    if (!emailDomain || !websiteDomain) return null;

    if (BLOCKED_DOMAINS.includes(emailDomain)) {
      return 'Registracija galima tik su įmonės el. paštu.';
    }

    if (emailDomain !== websiteDomain) {
      return 'El. pašto adresas turi sutapti su organizacijos svetainės domenu.';
    }

    return null;
  }

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    if (!firstName.trim() || !lastName.trim()) {
      setError('Vardas ir pavardė yra privalomi.');
      setLoading(false);
      return;
    }

    if (!orgName.trim() || !orgWebsite.trim()) {
      setError('Organizacijos pavadinimas ir svetainė yra privalomi.');
      setLoading(false);
      return;
    }

    const domainError = validateDomains();
    if (domainError) {
      setError(domainError);
      setLoading(false);
      return;
    }

    if (password.length < 12) {
      setError('Slaptažodis turi būti ne trumpesnis nei 12 simbolių.');
      setLoading(false);
      return;
    }

    if (password !== confirmPassword) {
      setError('Slaptažodžiai nesutampa.');
      setLoading(false);
      return;
    }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          firstName: firstName.trim(),
          lastName: lastName.trim(),
          email: email.trim().toLowerCase(),
          orgName: orgName.trim(),
          orgWebsite: extractDomain(orgWebsite),
          password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Registracijos klaida. Bandykite dar kartą.');
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
            <h1 className="text-2xl font-bold text-gray-900">
              Registracija gauta
            </h1>
            <p className="mt-4 text-gray-600">
              Jūsų registracijos prašymas sėkmingai pateiktas. Administratorius
              peržiūrės Jūsų paraišką ir gausite pranešimą el. paštu
              adresu <strong>{email}</strong>.
            </p>
            <Link
              href="/login"
              className="mt-6 inline-block text-blue-600 hover:text-blue-500 font-medium"
            >
              Grįžti į prisijungimą
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-md">
        <div>
          <h1 className="text-2xl font-bold text-center text-gray-900">
            scanit.lt
          </h1>
          <h2 className="mt-2 text-center text-lg text-gray-600">
            Naujos paskyros registracija
          </h2>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleRegister}>
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-700">
                  Vardas
                </label>
                <input
                  id="firstName"
                  type="text"
                  required
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                />
              </div>
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-700">
                  Pavardė
                </label>
                <input
                  id="lastName"
                  type="text"
                  required
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                />
              </div>
            </div>

            <div>
              <label htmlFor="orgName" className="block text-sm font-medium text-gray-700">
                Organizacijos pavadinimas
              </label>
              <input
                id="orgName"
                type="text"
                required
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                placeholder="UAB Pavyzdys"
              />
            </div>

            <div>
              <label htmlFor="orgWebsite" className="block text-sm font-medium text-gray-700">
                Organizacijos svetainė
              </label>
              <input
                id="orgWebsite"
                type="text"
                required
                value={orgWebsite}
                onChange={(e) => setOrgWebsite(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                placeholder="pavyzdys.lt"
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                El. pašto adresas (įmonės)
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                placeholder="vardas@organizacija.lt"
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
                minLength={12}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                placeholder="Mažiausiai 12 simbolių"
              />
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                Pakartokite slaptažodį
              </label>
              <input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                required
                minLength={12}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Registruojama...' : 'Registruotis'}
          </button>

          <p className="text-center text-sm text-gray-600">
            Jau turite paskyrą?{' '}
            <Link href="/login" className="text-blue-600 hover:text-blue-500 font-medium">
              Prisijungti
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
