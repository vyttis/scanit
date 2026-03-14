'use client';

import { useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { AdminNav } from '@/components/admin-nav';
import { formatLithuanianDateLong, formatLithuanianDateTimeLong } from '@/lib/utils/date';

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

const SECTOR_OPTIONS = Object.entries(SECTOR_LABELS).map(([value, label]) => ({ value, label }));

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
  } else if (score >= 41) {
    colorClass = 'bg-yellow-100 text-yellow-800';
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {score}
    </span>
  );
}

export function AdminOrganizationsClient({ organizations: initialOrganizations }: { organizations: Organization[] }) {
  const router = useRouter();
  const [orgs, setOrgs] = useState(initialOrganizations);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [scanMessage, setScanMessage] = useState<{ orgId: string; text: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Add organization form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [addForm, setAddForm] = useState({
    name: '',
    domain: '',
    contact_email: '',
    sector: '',
    verified: false,
  });
  const [addLoading, setAddLoading] = useState(false);

  // Confirm dialogs
  const [confirmAction, setConfirmAction] = useState<{ orgId: string; action: string; label: string } | null>(null);

  const filteredOrgs = useMemo(() => {
    if (!searchQuery.trim()) return orgs;
    const q = searchQuery.toLowerCase().trim();
    return orgs.filter(
      org =>
        org.name.toLowerCase().includes(q) ||
        org.domain.toLowerCase().includes(q)
    );
  }, [orgs, searchQuery]);

  function toggleExpanded(id: string) {
    setExpandedId(prev => (prev === id ? null : id));
  }

  function showSuccess(msg: string) {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 4000);
  }

  async function handleAddOrganization(e: React.FormEvent) {
    e.preventDefault();
    setAddLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/admin/organizations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(addForm),
      });

      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setShowAddForm(false);
        setAddForm({ name: '', domain: '', contact_email: '', sector: '', verified: false });
        showSuccess(`Organizacija „${data.organization?.name}" sukurta.`);
        router.refresh();
      } else {
        setError(data.error || 'Klaida kuriant organizaciją.');
      }
    } catch {
      setError('Tinklo klaida.');
    }

    setAddLoading(false);
  }

  async function handleOrgAction(orgId: string, action: string) {
    setLoadingAction(`${orgId}:${action}`);
    setError(null);

    try {
      if (action === 'delete') {
        const res = await fetch(`/api/admin/organizations?id=${orgId}`, { method: 'DELETE' });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          setOrgs(prev => prev.filter(o => o.id !== orgId));
          showSuccess('Organizacija ištrinta.');
          setConfirmAction(null);
          router.refresh();
        } else {
          setError(data.error || 'Klaida trinant organizaciją.');
        }
      } else {
        const res = await fetch('/api/admin/organizations', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: orgId, action }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          const labels: Record<string, string> = {
            verify: 'Domenas patvirtintas.',
            unverify: 'Domeno patvirtinimas atšauktas.',
          };
          // Optimistic update: immediately reflect verified state in UI
          if (data.organization) {
            setOrgs(prev => prev.map(o =>
              o.id === orgId ? { ...o, verified: data.organization.verified } : o
            ));
          }
          showSuccess(labels[action] || 'Atnaujinta.');
          setConfirmAction(null);
          router.refresh();
        } else {
          setError(data.error || 'Klaida.');
        }
      }
    } catch {
      setError('Tinklo klaida.');
    }

    setLoadingAction(null);
  }

  async function handleScan(orgId: string) {
    setLoadingAction(`${orgId}:scan`);
    setScanMessage(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: orgId }),
      });

      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setScanMessage({ orgId, text: 'Skenavimas pradėtas. Vyksta serveryje — galite uždaryti langą, rezultatai bus matomi grįžus.', type: 'info' });
        // Poll for completion
        if (data.scan_id) {
          const pollInterval = setInterval(async () => {
            try {
              const statusRes = await fetch(`/api/scan?id=${data.scan_id}`);
              if (statusRes.ok) {
                const statusData = await statusRes.json();
                if (statusData.status === 'completed') {
                  clearInterval(pollInterval);
                  setScanMessage({ orgId, text: 'Skenavimas baigtas.', type: 'success' });
                  router.refresh();
                } else if (statusData.status === 'failed') {
                  clearInterval(pollInterval);
                  setScanMessage({ orgId, text: 'Skenavimas nepavyko.', type: 'error' });
                }
              }
            } catch { /* continue polling */ }
          }, 5000);
          // Stop polling after 5 minutes max
          setTimeout(() => clearInterval(pollInterval), 300000);
        }
      } else {
        setScanMessage({ orgId, text: data.error || 'Klaida paleidžiant skenavimą.', type: 'error' });
      }
    } catch {
      setScanMessage({ orgId, text: 'Tinklo klaida.', type: 'error' });
    }

    setLoadingAction(null);
  }

  return (
    <div>
      <AdminNav />
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Organizacijų valdymas</h1>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors"
        >
          + Pridėti organizaciją
        </button>
      </div>

      {/* Messages */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm mb-4" role="alert">
          {error}
          <button onClick={() => setError(null)} className="ml-2 text-red-500 hover:text-red-700" aria-label="Uždaryti klaidos pranešimą">&times;</button>
        </div>
      )}
      {successMsg && (
        <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded text-sm mb-4">
          {successMsg}
        </div>
      )}

      {/* Add Organization Form */}
      {showAddForm && (
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Nauja organizacija</h2>
          <form onSubmit={handleAddOrganization} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Pavadinimas *</label>
                <input
                  type="text"
                  required
                  value={addForm.name}
                  onChange={e => setAddForm(f => ({ ...f, name: e.target.value }))}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md text-sm text-gray-900 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="VšĮ Organizacijos pavadinimas"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Domenas *</label>
                <input
                  type="text"
                  required
                  value={addForm.domain}
                  onChange={e => setAddForm(f => ({ ...f, domain: e.target.value }))}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md text-sm text-gray-900 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="organizacija.lt"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Kontaktinis el. paštas *</label>
                <input
                  type="email"
                  required
                  value={addForm.contact_email}
                  onChange={e => setAddForm(f => ({ ...f, contact_email: e.target.value }))}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md text-sm text-gray-900 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="info@organizacija.lt"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Sektorius</label>
                <select
                  value={addForm.sector}
                  onChange={e => setAddForm(f => ({ ...f, sector: e.target.value }))}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md text-sm text-gray-900 focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="">— Pasirinkite —</option>
                  {SECTOR_OPTIONS.map(s => (
                    <option key={s.value} value={s.value}>{s.label}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="verified"
                checked={addForm.verified}
                onChange={e => setAddForm(f => ({ ...f, verified: e.target.checked }))}
                className="h-4 w-4 text-blue-600 border-gray-300 rounded"
              />
              <label htmlFor="verified" className="text-sm text-gray-700">
                Iš karto patvirtinti domeną (aplenkti DNS tikrinimą)
              </label>
            </div>
            <div className="flex items-center gap-3">
              <button
                type="submit"
                disabled={addLoading}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {addLoading ? 'Kuriama...' : 'Sukurti organizaciją'}
              </button>
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors"
              >
                Atšaukti
              </button>
            </div>
          </form>
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
            aria-label="Ieškoti organizacijų"
          />
        </div>
      </div>

      {/* Summary */}
      <div className="mb-4 text-sm text-gray-500">
        Iš viso: {orgs.length} organizacij{orgs.length === 1 ? 'a' : orgs.length > 9 ? 'ų' : 'os'}
        {searchQuery.trim() && ` | Rasta: ${filteredOrgs.length}`}
      </div>

      {/* Confirm dialog */}
      {confirmAction && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 max-w-sm w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Patvirtinkite veiksmą</h3>
            <p className="text-sm text-gray-600 mb-4">{confirmAction.label}</p>
            <div className="flex items-center gap-3">
              <button
                onClick={() => handleOrgAction(confirmAction.orgId, confirmAction.action)}
                disabled={loadingAction !== null}
                className={`inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white transition-colors disabled:opacity-50 ${
                  confirmAction.action === 'delete' ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {loadingAction ? 'Vykdoma...' : 'Taip, tęsti'}
              </button>
              <button
                onClick={() => setConfirmAction(null)}
                disabled={loadingAction !== null}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                Atšaukti
              </button>
            </div>
          </div>
        </div>
      )}

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
                Rizikos balas
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
                onVerify={() => handleOrgAction(org.id, 'verify')}
                onUnverify={() => handleOrgAction(org.id, 'unverify')}
                onDelete={() =>
                  setConfirmAction({
                    orgId: org.id,
                    action: 'delete',
                    label: `Ar tikrai norite ištrinti organizaciją „${org.name}"? Bus pašalinti visi skenavimai, ataskaitos ir duomenys. Šio veiksmo negalima atšaukti.`,
                  })
                }
                onScan={() => handleScan(org.id)}
                isLoading={loadingAction?.startsWith(org.id) ?? false}
                scanMessage={scanMessage?.orgId === org.id ? scanMessage : null}
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
  onVerify: () => void;
  onUnverify: () => void;
  onDelete: () => void;
  onScan: () => void;
  isLoading: boolean;
  scanMessage: { text: string; type: 'success' | 'error' | 'info' } | null;
}

function OrgRow({
  org,
  isExpanded,
  onToggleExpand,
  onVerify,
  onUnverify,
  onDelete,
  onScan,
  isLoading,
  scanMessage,
}: OrgRowProps) {
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
          <div className="flex items-center gap-2 flex-wrap">
            {/* Verify / Unverify */}
            {!org.verified ? (
              <button
                onClick={onVerify}
                disabled={isLoading}
                className="inline-flex items-center px-3 py-1.5 border border-green-300 text-xs font-medium rounded-md text-green-700 bg-white hover:bg-green-50 transition-colors disabled:opacity-50"
              >
                Patvirtinti
              </button>
            ) : (
              <button
                onClick={onUnverify}
                disabled={isLoading}
                className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded-md text-gray-600 bg-white hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                Atšaukti patv.
              </button>
            )}

            {/* Scan */}
            <button
              onClick={onScan}
              disabled={isLoading}
              className="inline-flex items-center px-3 py-1.5 border border-blue-300 text-xs font-medium rounded-md text-blue-700 bg-white hover:bg-blue-50 transition-colors disabled:opacity-50"
            >
              Skenuoti
            </button>

            {/* Delete */}
            <button
              onClick={onDelete}
              disabled={isLoading}
              className="inline-flex items-center px-3 py-1.5 border border-red-300 text-xs font-medium rounded-md text-red-700 bg-white hover:bg-red-50 transition-colors disabled:opacity-50"
            >
              Ištrinti
            </button>

            {/* Scan message */}
            {scanMessage && (
              <span className={`text-xs ${
                scanMessage.type === 'success' ? 'text-green-600' :
                scanMessage.type === 'info' ? 'text-blue-600' :
                'text-red-600'
              }`}>
                {scanMessage.type === 'info' && (
                  <span className="inline-block w-2 h-2 rounded-full bg-blue-500 animate-pulse mr-1 align-middle" />
                )}
                {scanMessage.text}
              </span>
            )}
          </div>
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
                  {formatLithuanianDateLong(org.createdAt)}
                </p>
              </div>
              <div>
                <span className="font-medium text-gray-500">Paskutinio skenavimo data</span>
                <p className="mt-1 text-gray-900">
                  {org.lastScanDate
                    ? formatLithuanianDateTimeLong(org.lastScanDate)
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
