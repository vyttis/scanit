'use client';

import { useState, useMemo } from 'react';
import { AdminNav } from '@/components/admin-nav';
import { formatLithuanianDateTime } from '@/lib/utils/date';

interface AuditEntry {
  id: string;
  action: string;
  details: Record<string, unknown> | null;
  ipAddress: string;
  createdAt: string;
  userEmail: string;
  organizationName: string;
}

const ACTION_LABELS: Record<string, string> = {
  scan_triggered: 'Skenavimas paleistas',
  report_generated: 'Ataskaita sugeneruota',
  report_downloaded: 'Ataskaita atsisiųsta',
  login: 'Prisijungimas',
  login_failed: 'Nesėkmingas prisijungimas',
  domain_verified: 'Domenas patvirtintas',
  org_registered: 'Organizacija užregistruota',
  email_updated: 'El. paštas atnaujintas',
  user_approved: 'Vartotojas patvirtintas',
  user_rejected: 'Vartotojas atmestas',
};

const PAGE_SIZE = 50;

export function AdminAuditClient({ entries }: { entries: AuditEntry[] }) {
  const [actionFilter, setActionFilter] = useState<string>('');
  const [dateFrom, setDateFrom] = useState<string>('');
  const [dateTo, setDateTo] = useState<string>('');
  const [search, setSearch] = useState<string>('');
  const [page, setPage] = useState(0);

  // Get unique actions present in data
  const uniqueActions = useMemo(() => {
    const actions = new Set(entries.map(e => e.action));
    return Array.from(actions).sort();
  }, [entries]);

  // Filtered entries
  const filtered = useMemo(() => {
    return entries.filter(entry => {
      // Action filter
      if (actionFilter && entry.action !== actionFilter) return false;

      // Date range filter
      if (dateFrom) {
        const entryDate = new Date(entry.createdAt);
        const fromDate = new Date(dateFrom);
        fromDate.setHours(0, 0, 0, 0);
        if (entryDate < fromDate) return false;
      }
      if (dateTo) {
        const entryDate = new Date(entry.createdAt);
        const toDate = new Date(dateTo);
        toDate.setHours(23, 59, 59, 999);
        if (entryDate > toDate) return false;
      }

      // Search by email or org name
      if (search) {
        const q = search.toLowerCase();
        if (
          !entry.userEmail.toLowerCase().includes(q) &&
          !entry.organizationName.toLowerCase().includes(q)
        ) {
          return false;
        }
      }

      return true;
    });
  }, [entries, actionFilter, dateFrom, dateTo, search]);

  // Reset page when filters change
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages - 1);
  const pageEntries = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

  function formatDate(dateStr: string): string {
    return formatLithuanianDateTime(dateStr);
  }

  function formatDetails(details: Record<string, unknown> | null): string {
    if (!details) return '';
    try {
      return JSON.stringify(details, null, 0);
    } catch {
      return '';
    }
  }

  function exportCsv() {
    const headers = ['Data ir laikas', 'Vartotojas', 'Organizacija', 'Veiksmas', 'Detalės', 'IP adresas'];
    const rows = filtered.map(entry => [
      formatDate(entry.createdAt),
      entry.userEmail,
      entry.organizationName,
      ACTION_LABELS[entry.action] || entry.action,
      formatDetails(entry.details).replace(/"/g, '""'),
      entry.ipAddress,
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');

    const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `audito_zurnalas_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <AdminNav />
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-4 sm:mb-0">Audito žurnalas</h1>
        <button
          onClick={exportCsv}
          className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
        >
          Eksportuoti CSV
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white shadow rounded-lg p-4 mb-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Action filter */}
          <div>
            <label htmlFor="action-filter" className="block text-sm font-medium text-gray-700 mb-1">
              Veiksmo tipas
            </label>
            <select
              id="action-filter"
              value={actionFilter}
              onChange={e => { setActionFilter(e.target.value); setPage(0); }}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
            >
              <option value="">Visi veiksmai</option>
              {uniqueActions.map(action => (
                <option key={action} value={action}>
                  {ACTION_LABELS[action] || action}
                </option>
              ))}
            </select>
          </div>

          {/* Date from */}
          <div>
            <label htmlFor="date-from" className="block text-sm font-medium text-gray-700 mb-1">
              Data nuo
            </label>
            <input
              id="date-from"
              type="date"
              value={dateFrom}
              onChange={e => { setDateFrom(e.target.value); setPage(0); }}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
            />
          </div>

          {/* Date to */}
          <div>
            <label htmlFor="date-to" className="block text-sm font-medium text-gray-700 mb-1">
              Data iki
            </label>
            <input
              id="date-to"
              type="date"
              value={dateTo}
              onChange={e => { setDateTo(e.target.value); setPage(0); }}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
            />
          </div>

          {/* Search */}
          <div>
            <label htmlFor="search" className="block text-sm font-medium text-gray-700 mb-1">
              Paieška
            </label>
            <input
              id="search"
              type="text"
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(0); }}
              placeholder="El. paštas arba organizacija"
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
            />
          </div>
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-gray-500 mb-4">
        Rasta įrašų: {filtered.length}
      </p>

      {/* Table */}
      <div className="bg-white shadow overflow-hidden rounded-lg overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data ir laikas</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Vartotojas</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Organizacija</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Veiksmas</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detalės</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP adresas</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {pageEntries.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-sm text-gray-500">
                  Įrašų nerasta.
                </td>
              </tr>
            )}
            {pageEntries.map(entry => (
              <tr key={entry.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {formatDate(entry.createdAt)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {entry.userEmail || '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {entry.organizationName || '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                    {ACTION_LABELS[entry.action] || entry.action}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-500 max-w-xs truncate" title={formatDetails(entry.details)}>
                  {formatDetails(entry.details) || '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                  {entry.ipAddress || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <p className="text-sm text-gray-500">
            Puslapis {currentPage + 1} iš {totalPages}
          </p>
          <div className="flex space-x-2">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={currentPage === 0}
              className="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Ankstesnis
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={currentPage >= totalPages - 1}
              className="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Kitas
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
