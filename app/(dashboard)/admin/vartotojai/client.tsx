'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { AdminNav } from '@/components/admin-nav';

interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  status: string;
  role: string;
  createdAt: string;
  organizationName: string;
  organizationDomain: string;
}

export function AdminUsersClient({ users }: { users: User[] }) {
  const router = useRouter();
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  async function handleAction(userId: string, action: 'approve' | 'reject') {
    setLoadingId(userId);
    setError(null);

    try {
      const res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, action }),
      });

      if (res.ok) {
        router.refresh();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Klaida atliekant veiksmą. Bandykite dar kartą.');
      }
    } catch {
      setError('Tinklo klaida. Bandykite dar kartą.');
    }

    setLoadingId(null);
  }

  async function handleRoleChange(userId: string, newRole: string) {
    setLoadingId(userId);
    setError(null);

    try {
      const res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, action: 'change_role', role: newRole }),
      });

      if (res.ok) {
        router.refresh();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Klaida keičiant rolę.');
      }
    } catch {
      setError('Tinklo klaida. Bandykite dar kartą.');
    }

    setLoadingId(null);
  }

  async function handleSuspend(userId: string) {
    if (!confirm('Ar tikrai norite sustabdyti šį vartotoją?')) return;
    setLoadingId(userId);
    setError(null);

    try {
      const res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, action: 'suspend' }),
      });

      if (res.ok) {
        router.refresh();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Klaida sustabdant vartotoją.');
      }
    } catch {
      setError('Tinklo klaida. Bandykite dar kartą.');
    }

    setLoadingId(null);
  }

  const statusLabel = (status: string) => {
    switch (status) {
      case 'pending': return 'Laukia';
      case 'approved': return 'Patvirtintas';
      case 'rejected': return 'Atmestas';
      case 'suspended': return 'Sustabdytas';
      default: return status;
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-800';
      case 'approved': return 'bg-green-100 text-green-800';
      case 'rejected': return 'bg-red-100 text-red-800';
      case 'suspended': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const searchLower = search.toLowerCase();
  const filteredUsers = users.filter(u => {
    const matchesSearch = !search ||
      `${u.firstName} ${u.lastName}`.toLowerCase().includes(searchLower) ||
      u.email.toLowerCase().includes(searchLower) ||
      u.organizationName.toLowerCase().includes(searchLower);
    const matchesStatus = statusFilter === 'all' || u.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const pendingUsers = filteredUsers.filter(u => u.status === 'pending');
  const otherUsers = filteredUsers.filter(u => u.status !== 'pending');

  return (
    <div>
      <AdminNav />
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Vartotojų valdymas</h1>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm mb-6" role="alert">
          {error}
        </div>
      )}

      {/* Search and filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="flex-1">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Ieškoti pagal vardą, el. paštą ar organizaciją..."
            className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            aria-label="Paieška"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
          aria-label="Filtruoti pagal būseną"
        >
          <option value="all">Visos būsenos</option>
          <option value="pending">Laukia</option>
          <option value="approved">Patvirtinti</option>
          <option value="rejected">Atmesti</option>
          <option value="suspended">Sustabdyti</option>
        </select>
      </div>

      {pendingUsers.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Laukiantys patvirtinimo ({pendingUsers.length})
          </h2>
          <div className="bg-white shadow overflow-hidden rounded-lg overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Vardas, pavardė</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">El. paštas</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Organizacija</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Svetainė</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Veiksmai</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {pendingUsers.map(user => (
                  <tr key={user.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {user.firstName} {user.lastName}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.email}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.organizationName}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.organizationDomain}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(user.createdAt).toLocaleDateString('lt-LT')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm space-x-2">
                      <button
                        onClick={() => handleAction(user.id, 'approve')}
                        disabled={loadingId === user.id}
                        className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md text-white bg-green-600 hover:bg-green-700 disabled:opacity-50"
                      >
                        Patvirtinti
                      </button>
                      <button
                        onClick={() => handleAction(user.id, 'reject')}
                        disabled={loadingId === user.id}
                        className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md text-white bg-red-600 hover:bg-red-700 disabled:opacity-50"
                      >
                        Atmesti
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {pendingUsers.length === 0 && (statusFilter === 'all' || statusFilter === 'pending') && (
        <div className="bg-white rounded-lg shadow p-6 mb-8 text-center text-gray-500">
          Nėra laukiančių patvirtinimo vartotojų.
        </div>
      )}

      {otherUsers.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Visi vartotojai ({otherUsers.length})
          </h2>
          <div className="bg-white shadow overflow-hidden rounded-lg overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Vardas, pavardė</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">El. paštas</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Organizacija</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rolė</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Būsena</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Veiksmai</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {otherUsers.map(user => (
                  <tr key={user.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {user.firstName} {user.lastName}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.email}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.organizationName}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={user.role}
                        onChange={(e) => handleRoleChange(user.id, e.target.value)}
                        disabled={loadingId === user.id || user.role === 'superadmin'}
                        className="text-xs border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50"
                        aria-label={`Keisti ${user.firstName} ${user.lastName} rolę`}
                      >
                        <option value="admin">Administratorius</option>
                        <option value="viewer">Stebėtojas</option>
                        {user.role === 'superadmin' && <option value="superadmin">Superadminas</option>}
                      </select>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColor(user.status)}`}>
                        {statusLabel(user.status)}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(user.createdAt).toLocaleDateString('lt-LT')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {user.status === 'approved' && user.role !== 'superadmin' && (
                        <button
                          onClick={() => handleSuspend(user.id)}
                          disabled={loadingId === user.id}
                          className="text-xs text-red-600 hover:text-red-800 font-medium disabled:opacity-50"
                        >
                          Sustabdyti
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
