import { createServerSupabaseClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';

const ACTION_LABELS: Record<string, string> = {
  scan_triggered: 'Skenavimas paleistas',
  report_generated: 'Ataskaita sugeneruota',
  report_downloaded: 'Ataskaita atsisiųsta',
  login: 'Prisijungimas',
  login_failed: 'Nesėkmingas prisijungimas',
  domain_verified: 'Domenas patvirtintas',
  org_registered: 'Organizacija užregistruota',
  email_updated: 'El. paštas atnaujintas',
};

export default async function AuditLogPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    redirect('/login');
  }

  // Only admins can view audit log
  const { data: profile } = await supabase
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  if (!profile?.org_id || profile.role !== 'admin') {
    return (
      <div className="max-w-2xl mx-auto mt-8">
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <h1 className="text-xl font-bold text-gray-900 mb-4">Prieiga uždrausta</h1>
          <p className="text-gray-600">
            Audito žurnalą gali peržiūrėti tik administratoriai.
          </p>
          <Link
            href="/settings"
            className="inline-block mt-4 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700"
          >
            Grįžti į nustatymus
          </Link>
        </div>
      </div>
    );
  }

  // Fetch last 50 audit log entries for this org
  const { data: logs } = await supabase
    .from('audit_log')
    .select('*')
    .eq('org_id', profile.org_id)
    .order('created_at', { ascending: false })
    .limit(50);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Audito žurnalas</h1>
        <Link
          href="/settings"
          className="text-sm text-blue-600 hover:text-blue-800"
        >
          Grįžti į nustatymus
        </Link>
      </div>

      <p className="text-sm text-gray-600">
        Paskutiniai 50 sistemos veiksmų. Audito žurnalas yra nekeičiamas — įrašai negali būti redaguojami ar trinami.
      </p>

      {!logs || logs.length === 0 ? (
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <p className="text-gray-500">Audito žurnale įrašų dar nėra.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-md overflow-hidden overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data ir laikas</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Veiksmas</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detalės</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP adresas</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm text-gray-900 whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString('lt-LT')}
                  </td>
                  <td className="px-6 py-4">
                    <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-800">
                      {ACTION_LABELS[log.action] || log.action}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 max-w-xs truncate">
                    {log.details ? (
                      <span title={JSON.stringify(log.details)}>
                        {formatDetails(log.action, log.details as Record<string, unknown>)}
                      </span>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500 font-mono">
                    {log.ip_address || '—'}
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

function formatDetails(action: string, details: Record<string, unknown>): string {
  switch (action) {
    case 'scan_triggered':
      return `Domenas: ${details.domain ?? '—'}, tipas: ${details.scan_type ?? '—'}`;
    case 'report_generated':
      return `Rizikos balas: ${details.risk_score ?? '—'}`;
    case 'report_downloaded':
      return `Ataskaitos ID: ${String(details.report_id ?? '—').slice(0, 8)}...`;
    default:
      return Object.entries(details)
        .slice(0, 3)
        .map(([k, v]) => `${k}: ${String(v)}`)
        .join(', ');
  }
}
