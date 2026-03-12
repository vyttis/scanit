import { createServerSupabaseClient } from '@/lib/supabase/server';

export default async function ScansPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data: profile } = await supabase
    .from('profiles')
    .select('org_id')
    .eq('id', user.id)
    .single();

  if (!profile?.org_id) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Pirmiausia užregistruokite organizaciją nustatymuose.</p>
      </div>
    );
  }

  const { data: scans } = await supabase
    .from('scans')
    .select('*')
    .eq('org_id', profile.org_id)
    .order('created_at', { ascending: false });

  const statusLabels: Record<string, string> = {
    queued: 'Laukiama eilėje',
    running: 'Vykdomas',
    completed: 'Baigtas',
    failed: 'Nepavyko',
  };

  const statusColors: Record<string, string> = {
    queued: 'bg-gray-100 text-gray-800',
    running: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Skenavimų istorija</h1>

      {!scans || scans.length === 0 ? (
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <p className="text-gray-500">Skenavimų dar nebuvo atlikta.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-md overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tipas</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Būsena</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trukmė</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="px-6 py-4 text-sm text-gray-900">
                    {new Date(scan.created_at).toLocaleString('lt-LT')}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {scan.scan_type === 'light' ? 'Lengvas' : 'Gilus'}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${statusColors[scan.status] || ''}`}>
                      {statusLabels[scan.status] || scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {scan.started_at && scan.completed_at
                      ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)} sek.`
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
