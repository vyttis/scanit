'use client';

import { useState, useEffect, useCallback } from 'react';
import { createClient } from '@/lib/supabase/client';
import { isValidDomain, sanitizeDomain, isValidEmail } from '@/lib/validations';
import type { Organization, OrganizationSector } from '@/types/database';

const SECTORS: { value: OrganizationSector; label: string }[] = [
  { value: 'energetika', label: 'Energetika' },
  { value: 'transportas', label: 'Transportas' },
  { value: 'sveikatos_apsauga', label: 'Sveikatos apsauga' },
  { value: 'skaitmenine_infrastruktura', label: 'Skaitmeninė infrastruktūra' },
  { value: 'it_paslaugos', label: 'IT paslaugos' },
  { value: 'viesasis_administravimas', label: 'Viešasis administravimas' },
  { value: 'vandentiekis', label: 'Vandentiekis' },
  { value: 'bankininkiste', label: 'Bankininkystė' },
  { value: 'maisto_pramone', label: 'Maisto pramonė' },
  { value: 'gamyba', label: 'Gamyba' },
  { value: 'moksliniai_tyrimai', label: 'Moksliniai tyrimai' },
  { value: 'pasto_paslaugos', label: 'Pašto paslaugos' },
  { value: 'atlieku_tvarkymas', label: 'Atliekų tvarkymas' },
];

export default function SettingsPage() {
  const supabase = createClient();
  const [org, setOrg] = useState<Organization | null>(null);
  const [hasOrg, setHasOrg] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  // Registration form
  const [orgName, setOrgName] = useState('');
  const [domain, setDomain] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [sector, setSector] = useState<OrganizationSector | ''>('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formLoading, setFormLoading] = useState(false);

  // Verification
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verifyResult, setVerifyResult] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;

    const { data: profile } = await supabase
      .from('profiles')
      .select('org_id')
      .eq('id', user.id)
      .single();

    if (!profile?.org_id) {
      setHasOrg(false);
      setLoading(false);
      return;
    }

    const { data: orgData } = await supabase
      .from('organizations')
      .select('*')
      .eq('id', profile.org_id)
      .single();

    if (orgData) {
      setOrg(orgData as Organization);
      setHasOrg(true);
    } else {
      setHasOrg(false);
    }
    setLoading(false);
  }, [supabase]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  async function handleRegisterOrg(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setFormLoading(true);

    const cleanDomain = sanitizeDomain(domain);

    if (!orgName.trim()) {
      setFormError('Įveskite organizacijos pavadinimą.');
      setFormLoading(false);
      return;
    }

    if (!isValidDomain(cleanDomain)) {
      setFormError('Neteisingas domeno formatas. Pvz.: organizacija.lt');
      setFormLoading(false);
      return;
    }

    if (!isValidEmail(contactEmail)) {
      setFormError('Neteisingas el. pašto formatas.');
      setFormLoading(false);
      return;
    }

    // Call server-side API to register org (generates verification token securely)
    const response = await fetch('/api/verify-domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'register',
        name: orgName.trim(),
        domain: cleanDomain,
        contact_email: contactEmail.trim(),
        sector: sector || null,
      }),
    });

    const result = await response.json();

    if (!response.ok) {
      setFormError(result.error || 'Registracijos klaida.');
      setFormLoading(false);
      return;
    }

    await loadData();
    setFormLoading(false);
  }

  async function handleVerifyDomain() {
    setVerifyLoading(true);
    setVerifyResult(null);

    const response = await fetch('/api/verify-domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'verify',
      }),
    });

    const result = await response.json();

    if (response.ok && result.verified) {
      setVerifyResult('success');
      await loadData();
    } else {
      setVerifyResult(result.error || 'DNS TXT įrašas nerastas. Patikrinkite, ar teisingai pridėjote įrašą.');
    }

    setVerifyLoading(false);
  }

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <p className="text-gray-500">Kraunama...</p>
      </div>
    );
  }

  // Organization registration form
  if (!hasOrg) {
    return (
      <div className="max-w-2xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-900 mb-6">
          Organizacijos registracija
        </h1>

        <form onSubmit={handleRegisterOrg} className="bg-white rounded-lg shadow-md p-6 space-y-4">
          {formError && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {formError}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Organizacijos pavadinimas
            </label>
            <input
              type="text"
              required
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
              placeholder="UAB Pavyzdys"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Domenas
            </label>
            <input
              type="text"
              required
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
              placeholder="organizacija.lt"
            />
            <p className="mt-1 text-xs text-gray-500">
              Įveskite pagrindinį domeno vardą be https:// ar www.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Kontaktinis el. paštas
            </label>
            <input
              type="email"
              required
              value={contactEmail}
              onChange={(e) => setContactEmail(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
              placeholder="it@organizacija.lt"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              KSĮ sektorius
            </label>
            <select
              value={sector}
              onChange={(e) => setSector(e.target.value as OrganizationSector)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
            >
              <option value="">Pasirinkite sektorių</option>
              {SECTORS.map((s) => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
          </div>

          <button
            type="submit"
            disabled={formLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {formLoading ? 'Registruojama...' : 'Registruoti organizaciją'}
          </button>
        </form>
      </div>
    );
  }

  // Organization settings & domain verification
  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Nustatymai</h1>

      {/* Organization info */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Organizacijos informacija</h2>
        <dl className="space-y-3">
          <div className="flex justify-between">
            <dt className="text-sm text-gray-500">Pavadinimas</dt>
            <dd className="text-sm text-gray-900">{org?.name}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-sm text-gray-500">Domenas</dt>
            <dd className="text-sm text-gray-900">{org?.domain}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-sm text-gray-500">Kontaktinis el. paštas</dt>
            <dd className="text-sm text-gray-900">{org?.contact_email}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-sm text-gray-500">Domeno būsena</dt>
            <dd className={`text-sm font-medium ${org?.verified ? 'text-green-600' : 'text-yellow-600'}`}>
              {org?.verified ? 'Patvirtintas' : 'Nepatvirtintas'}
            </dd>
          </div>
        </dl>
      </div>

      {/* Domain verification */}
      {org && !org.verified && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Domeno patvirtinimas</h2>
          <p className="text-sm text-gray-600 mb-4">
            Norėdami patvirtinti domeno nuosavybę, pridėkite šį DNS TXT įrašą prie savo domeno:
          </p>

          <div className="bg-gray-50 border border-gray-200 rounded-md p-4 mb-4">
            <p className="text-xs text-gray-500 mb-1">DNS TXT įrašas:</p>
            <code className="text-sm font-mono text-gray-900 break-all">
              {org.verification_token}
            </code>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-md p-4 mb-4 text-sm text-blue-800">
            <p className="font-medium mb-2">Instrukcijos:</p>
            <ol className="list-decimal list-inside space-y-1">
              <li>Prisijunkite prie savo DNS valdymo skydelio</li>
              <li>Pridėkite naują TXT įrašą savo domenui ({org.domain})</li>
              <li>Įrašo reikšmė: <code className="bg-blue-100 px-1 rounded">{org.verification_token}</code></li>
              <li>Palaukite kol DNS pakeitimai įsigalios (iki 24 val.)</li>
              <li>Spauskite mygtuką &ldquo;Tikrinti domeną&rdquo;</li>
            </ol>
          </div>

          {verifyResult && verifyResult !== 'success' && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm mb-4">
              {verifyResult}
            </div>
          )}

          {verifyResult === 'success' && (
            <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded text-sm mb-4">
              Domenas sėkmingai patvirtintas! Dabar galite pradėti skenavimą.
            </div>
          )}

          <button
            onClick={handleVerifyDomain}
            disabled={verifyLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {verifyLoading ? 'Tikrinama...' : 'Tikrinti domeną'}
          </button>
        </div>
      )}

      {org?.verified && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <p className="text-sm text-green-800">
            Domenas <strong>{org.domain}</strong> patvirtintas. Galite pradėti skenavimą iš valdymo skydelio.
          </p>
        </div>
      )}
    </div>
  );
}
