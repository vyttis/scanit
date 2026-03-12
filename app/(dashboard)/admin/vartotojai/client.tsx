'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  status: string;
  createdAt: string;
  organizationName: string;
  organizationDomain: string;
}

export function AdminUsersClient({ users }: { users: User[] }) {
  const router = useRouter();
  const [loadingId, setLoadingId] = useState<string | null>(null);

  async function handleAction(userId: string, action: 'approve' | 'reject') {
    setLoadingId(userId);

    try {
      const res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, action }),
      });

      if (res.ok) {
        router.refresh();
      }
    } catch (err) {
      console.error('Action error:', err);
    }

    setLoadingId(null);
  }

  const pendingUsers = users.filter(u => u.status === 'pending');
  const otherUsers = users.filter(u => u.status !== 'pending');

  const statusLabel = (status: string) => {
    switch (status) {
      case 'pending': return 'Laukia';
      case 'approved': return 'Patvirtintas';
      case 'rejected': return 'Atmestas';
      default: return status;
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-800';
      case 'approved': return 'bg-green-100 text-green-800';
      case 'rejected': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Vartotojų valdymas</h1>

      {pendingUsers.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Laukiantys patvirtinimo ({pendingUsers.length})
          </h2>
          <div className="bg-white shadow overflow-hidden rounded-lg">
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

      {pendingUsers.length === 0 && (
        <div className="bg-white rounded-lg shadow p-6 mb-8 text-center text-gray-500">
          Nėra laukiančių patvirtinimo vartotojų.
        </div>
      )}

      {otherUsers.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Visi vartotojai</h2>
          <div className="bg-white shadow overflow-hidden rounded-lg">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Vardas, pavardė</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">El. paštas</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Organizacija</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Būsena</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data</th>
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
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColor(user.status)}`}>
                        {statusLabel(user.status)}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(user.createdAt).toLocaleDateString('lt-LT')}
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
