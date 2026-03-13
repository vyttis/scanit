'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

interface DataEnrichmentProps {
  orgId: string;
  domainVerified: boolean;
  currentIpRanges: string[];
  currentEmails: string[];
  currentSubdomains: string[];
}

const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

function isValidCidr(cidr: string): boolean {
  if (!CIDR_REGEX.test(cidr)) return false;
  const [ip, prefix] = cidr.split('/');
  const parts = ip.split('.').map(Number);
  const prefixNum = Number(prefix);
  return (
    parts.every((p) => p >= 0 && p <= 255) &&
    prefixNum >= 0 &&
    prefixNum <= 32
  );
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidSubdomain(sub: string): boolean {
  return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(sub);
}

export function DataEnrichment({
  orgId,
  domainVerified,
  currentIpRanges,
  currentEmails,
  currentSubdomains,
}: DataEnrichmentProps) {
  const router = useRouter();
  const [ipRanges, setIpRanges] = useState(currentIpRanges.join('\n'));
  const [emails, setEmails] = useState(currentEmails.join('\n'));
  const [subdomains, setSubdomains] = useState(currentSubdomains.join('\n'));
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function saveField(field: 'ip_ranges' | 'employee_emails' | 'subdomains') {
    setError(null);
    setSuccess(null);
    setSaving(field);

    let values: string[] = [];
    if (field === 'ip_ranges') {
      values = ipRanges
        .split(/[\n,]/)
        .map((v) => v.trim())
        .filter(Boolean);
      const invalid = values.find((v) => !isValidCidr(v));
      if (invalid) {
        setError(`Netinkamas CIDR formatas: ${invalid}. Pavyzdys: 192.168.1.0/24`);
        setSaving(null);
        return;
      }
    } else if (field === 'employee_emails') {
      values = emails
        .split(/[\n,]/)
        .map((v) => v.trim().toLowerCase())
        .filter(Boolean);
      const invalid = values.find((v) => !isValidEmail(v));
      if (invalid) {
        setError(`Netinkamas el. pašto formatas: ${invalid}`);
        setSaving(null);
        return;
      }
    } else {
      values = subdomains
        .split(/[\n,]/)
        .map((v) => v.trim().toLowerCase())
        .filter(Boolean);
      const invalid = values.find((v) => !isValidSubdomain(v));
      if (invalid) {
        setError(`Netinkamas subdomeno formatas: ${invalid}`);
        setSaving(null);
        return;
      }
    }

    try {
      const res = await fetch('/api/enrichment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgId, field, values }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Klaida išsaugant duomenis.');
        setSaving(null);
        return;
      }

      setSuccess(
        field === 'ip_ranges'
          ? 'IP rangai išsaugoti.'
          : field === 'employee_emails'
            ? 'El. paštai išsaugoti.'
            : 'Subdomainai išsaugoti.',
      );
      router.refresh();
    } catch {
      setError('Tinklo klaida.');
    }

    setSaving(null);
  }

  const cards = [
    {
      key: 'domain' as const,
      title: 'Domenas',
      status: domainVerified ? 'verified' : 'pending',
      statusText: domainVerified ? 'Patvirtintas' : 'Nepatvirtintas',
    },
    {
      key: 'ip_ranges' as const,
      title: 'IP adresų rangai',
      count: currentIpRanges.length,
    },
    {
      key: 'employee_emails' as const,
      title: 'El. pašto sąrašas',
      count: currentEmails.length,
    },
    {
      key: 'subdomains' as const,
      title: 'Subdomainų sąrašas',
      count: currentSubdomains.length,
    },
  ];

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-lg font-bold text-gray-900 mb-1">
        Praturtinkite savo skenavimą
      </h2>
      <p className="text-sm text-gray-500 mb-6">
        Kuo daugiau duomenų pateiksite, tuo išsamesnę saugumo ataskaitą gausite.
      </p>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-4" role="alert">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg text-sm mb-4">
          {success}
        </div>
      )}

      {/* Status cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {cards.map((card) => (
          <div
            key={card.key}
            className={`rounded-lg border p-3 text-center ${
              card.key === 'domain' && card.status === 'verified'
                ? 'border-green-200 bg-green-50'
                : card.key !== 'domain' && (card.count ?? 0) > 0
                  ? 'border-blue-200 bg-blue-50'
                  : 'border-gray-200 bg-gray-50'
            }`}
          >
            <div className="text-lg mb-1">
              {card.key === 'domain' && card.status === 'verified'
                ? '✅'
                : card.key !== 'domain' && (card.count ?? 0) > 0
                  ? '✅'
                  : '➕'}
            </div>
            <div className="text-sm font-medium text-gray-900">{card.title}</div>
            <div className="text-xs text-gray-500">
              {card.key === 'domain'
                ? card.statusText
                : `${card.count ?? 0} įrašų`}
            </div>
          </div>
        ))}
      </div>

      {/* IP ranges */}
      <div className="space-y-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            IP adresų rangai (CIDR formatas)
          </label>
          <textarea
            value={ipRanges}
            onChange={(e) => setIpRanges(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm font-mono"
            placeholder="192.168.1.0/24&#10;10.0.0.0/8"
          />
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-gray-400">
              Po vieną CIDR rangą eilutėje
            </span>
            <button
              type="button"
              onClick={() => saveField('ip_ranges')}
              disabled={saving === 'ip_ranges'}
              className="px-4 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              {saving === 'ip_ranges' ? 'Saugoma...' : 'Pridėti IP rangus'}
            </button>
          </div>
        </div>

        {/* Employee emails */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Darbuotojų el. paštai
          </label>
          <textarea
            value={emails}
            onChange={(e) => setEmails(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
            placeholder="vardas@organizacija.lt&#10;kitas@organizacija.lt"
          />
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-gray-400">
              Po vieną el. paštą eilutėje arba įkelkite CSV failą
            </span>
            <button
              type="button"
              onClick={() => saveField('employee_emails')}
              disabled={saving === 'employee_emails'}
              className="px-4 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              {saving === 'employee_emails' ? 'Saugoma...' : 'Įkelti el. paštus'}
            </button>
          </div>
        </div>

        {/* Subdomains */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Subdomainai
          </label>
          <textarea
            value={subdomains}
            onChange={(e) => setSubdomains(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm font-mono"
            placeholder="mail.organizacija.lt&#10;vpn.organizacija.lt"
          />
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-gray-400">
              Po vieną subdomeną eilutėje
            </span>
            <button
              type="button"
              onClick={() => saveField('subdomains')}
              disabled={saving === 'subdomains'}
              className="px-4 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              {saving === 'subdomains' ? 'Saugoma...' : 'Pridėti subdomainus'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
