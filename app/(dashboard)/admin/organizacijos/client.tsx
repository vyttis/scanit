'use client';

import { useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { AdminNav } from '@/components/admin-nav';

const SECTOR_LABELS: Record<string, string> = {
  energetika: 'Energetika',
  transportas: 'Transportas',
  sveikatos_apsauga: 'Sveikatos apsauga',
  skaitmenine_infrastruktura: 'Skaitmeninė infrastruktūra',
  it_paslaugos: 'IT paslaugos',
  viesasis_administravimas: 'Viešasis administravimas',
  vandentiekis: 'Vandentiekis',
  bankininkiste: 'Bankininkystė',
  maisto_pramone: 'Maisto pramonė',
  gamyba: 'Gamyba',
  moksliniai_tyrimai: 'Moksliniai tyrimai',
  pasto_paslaugos: 'Pašto paslaugos',
  atlieku_tvarkymas: 'Atliekų tvarkymas',
};

interface Organization {
  id: string;
  name: string;
  domain: string;
  verified: boolean;
  contactEmail: string;
  sector: string | null;
  createdAt: string;
  scanCount: number;
  latestRiskScore: number | null;
  totalFindings: number;
  lastScanDate: string | null;
}

function RiskScoreBadge({ score }: { score: number | null }) {
  if (score === null) {
    return <span className="text-sm text-gray-400">-</span>;
  }

  let colorClass = 'bg-green-100 text-green-800';
  if (score >= 70) {
    colorClass = 'bg-red-100 text-red-800';
  } else if (score >= 40) {
    colorClass = 'bg-yellow-100 text-yellow-800';
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {score}
    </span>
  );
}

export function AdminOrganizationsClient({ organizations }: { organizations: Organization[] }) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [suspendingId, setSuspendingId] = useState<string | null>(null);
  const [confirmSuspendId, setConfirmSuspendId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const filteredOrgs = useMemo(() => {
    if (!searchQuery.trim()) return organizations;
    const q = searchQuery.toLowerCase().trim();
    return organizations.filter(
      org =>
        org.name.toLowerCase().includes(q) ||
        org.domain.toLowerCase().includes(q)
    );
  }, [organizations, searchQuery]);

  function toggleExpanded(id: string) {
    setExpandedId(prev => (prev === id ? null : id));
  }

  async function handleSuspend(orgId: string) {
    setSuspendingId(orgId);
    setError(null);

    try {
      const res = await fetch('/api/admin/organizations/suspend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organizationId: orgId }),
      });

      if (res.ok) {
        setConfirmSuspendId(null);
        router.refresh();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Klaida sustabdant organizaciją. Bandykite dar kartą.');
      }
    } catch {
      setError('Tinklo klaida. Bandykite dar kartą.');
    }

    setSuspendingId(null);
  }

  return (
    <div>
      <AdminNav />
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Organizacijų valdymas</h1>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm mb-6" role="alert">
          {error}
        </div>
      )}

      {/* Search */}
      <div className="mb-6">
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg className="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
            </svg>
          </div>
          <input
            type="text"
            placeholder="Ieškoti pagal pavadinimą arba domeną..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white text-gray-900 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
          />
        </div>
      </div>

      {/* Summary */}
      <div className="mb-4 text-sm text-gray-500">
        Iš viso: {organizations.length} organizacij{organizations.length === 1 ? 'a' : organizations.length > 9 ? 'ų' : 'os'}
        {searchQuery.trim() && ` | Rasta: ${filteredOrgs.length}`}
      </div>

      {/* Table */}
      <div className="bg-white shadow overflow-hidden rounded-lg overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Pavadinimas
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Domenas
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Būsena
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Sektorius
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Skenavimų sk.
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Paskutinis rizikos balas
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Veiksmai
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredOrgs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-sm text-gray-500">
                  {searchQuery.trim()
                    ? 'Nerasta organizacijų pagal paieškos užklausą.'
                    : 'Nėra registruotų organizacijų.'}
                </td>
              </tr>
            )}
            {filteredOrgs.map(org => (
              <OrgRow
                key={org.id}
                org={org}
                isExpanded={expandedId === org.id}
                onToggleExpand={() => toggleExpanded(org.id)}
                confirmSuspendId={confirmSuspendId}
                onConfirmSuspend={() => setConfirmSuspendId(org.id)}
                onCancelSuspend={() => setConfirmSuspendId(null)}
                onSuspend={() => handleSuspend(org.id)}
                isSuspending={suspendingId === org.id}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface OrgRowProps {
  org: Organization;
  isExpanded: boolean;
  onToggleExpand: () => void;
  confirmSuspendId: string | null;
  onConfirmSuspend: () => void;
  onCancelSuspend: () => void;
  onSuspend: () => void;
  isSuspending: boolean;
}

function OrgRow({
  org,
  isExpanded,
  onToggleExpand,
  confirmSuspendId,
  onConfirmSuspend,
  onCancelSuspend,
  onSuspend,
  isSuspending,
}: OrgRowProps) {
  const isConfirming = confirmSuspendId === org.id;

  return (
    <>
      <tr
        className="hover:bg-gray-50 cursor-pointer transition-colors"
        onClick={onToggleExpand}
      >
        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
          <div className="flex items-center gap-2">
            <svg
              className={`h-4 w-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clipRule="evenodd" />
            </svg>
            {org.name}
          </div>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
          {org.domain}
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
          {org.verified ? (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
              Patvirtintas
            </span>
          ) : (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
              Nepatvirtintas
            </span>
          )}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
          {org.sector ? (SECTOR_LABELS[org.sector] || org.sector) : '-'}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
          {org.scanCount}
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
          <RiskScoreBadge score={org.latestRiskScore} />
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm" onClick={e => e.stopPropagation()}>
          {isConfirming ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-red-600 font-medium">Tikrai sustabdyti?</span>
              <button
                onClick={onSuspend}
                disabled={isSuspending}
                className="inline-flex items-center px-2 py-1 border border-transparent text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700 disabled:opacity-50"
              >
                {isSuspending ? 'Vykdoma...' : 'Taip'}
              </button>
              <button
                onClick={onCancelSuspend}
                disabled={isSuspending}
                className="inline-flex items-center px-2 py-1 border border-gray-300 text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
              >
                Ne
              </button>
            </div>
          ) : (
            <button
              onClick={onConfirmSuspend}
              className="inline-flex items-center px-3 py-1.5 border border-red-300 text-xs font-medium rounded-md text-red-700 bg-white hover:bg-red-50 transition-colors"
            >
              Sustabdyti
            </button>
          )}
        </td>
      </tr>

      {/* Expanded details row */}
      {isExpanded && (
        <tr className="bg-gray-50">
          <td colSpan={7} className="px-6 py-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="font-medium text-gray-500">Kontaktinis el. paštas</span>
                <p className="mt-1 text-gray-900">{org.contactEmail}</p>
              </div>
              <div>
                <span className="font-medium text-gray-500">Registracijos data</span>
                <p className="mt-1 text-gray-900">
                  {new Date(org.createdAt).toLocaleDateString('lt-LT', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                  })}
                </p>
              </div>
              <div>
                <span className="font-medium text-gray-500">Paskutinio skenavimo data</span>
                <p className="mt-1 text-gray-900">
                  {org.lastScanDate
                    ? new Date(org.lastScanDate).toLocaleDateString('lt-LT', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })
                    : 'Neskenuota'}
                </p>
              </div>
              <div>
                <span className="font-medium text-gray-500">Iš viso nustatytų trūkumų</span>
                <p className="mt-1 text-gray-900">{org.totalFindings}</p>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
