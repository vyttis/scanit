import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import Link from 'next/link';
import { ReportDownloadButton } from '@/components/report-download-button';
import { formatLithuanianDateTime } from '@/lib/utils/date';

export default async function ScansPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  // Use service role for profile read — superadmin has org_id=NULL which breaks RLS
  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  if (!isSuperadmin && !profile?.org_id) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Pirmiausia užregistruokite organizaciją nustatymuose.</p>
      </div>
    );
  }

  // Superadmin sees all scans; regular users see only their org's scans
  const client = isSuperadmin ? createServiceRoleClient() : supabase;

  let scansQuery = client
    .from('scans')
    .select('*, organizations(name)')
    .order('created_at', { ascending: false });
  if (!isSuperadmin) {
    scansQuery = scansQuery.eq('org_id', profile!.org_id!);
  }
  const { data: scans } = await scansQuery;

  let reportsQuery = client
    .from('reports')
    .select('id, scan_id, risk_score, critical_count, high_count, medium_count, low_count, pdf_path');
  if (!isSuperadmin) {
    reportsQuery = reportsQuery.eq('org_id', profile!.org_id!);
  }
  const { data: reports } = await reportsQuery;

  const reportByScanId = new Map(
    (reports ?? []).map((r) => [r.scan_id, r]),
  );

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

  function riskScoreColor(score: number | null): string {
    if (score === null) return 'text-gray-400';
    if (score >= 70) return 'text-red-600';
    if (score >= 41) return 'text-yellow-600';
    return 'text-green-600';
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Skenavimų istorija</h1>

      {!scans || scans.length === 0 ? (
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <p className="text-gray-500">Skenavimų dar nebuvo atlikta.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-md overflow-hidden overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {isSuperadmin && (
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Organizacija</th>
                )}
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tipas</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Būsena</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rizikos balas</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trūkumai</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trukmė</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Ataskaita</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {scans.map((scan) => {
                const report = reportByScanId.get(scan.id);
                return (
                  <tr key={scan.id} className="hover:bg-gray-50">
                    {isSuperadmin && (
                      <td className="px-6 py-4 text-sm text-gray-900 font-medium">
                        {(scan as Record<string, unknown>).organizations
                          ? ((scan as Record<string, unknown>).organizations as { name: string }).name
                          : '—'}
                      </td>
                    )}
                    <td className="px-6 py-4 text-sm text-gray-900">
                      <Link href={`/scans/${scan.id}`} className="text-blue-600 hover:text-blue-800 hover:underline">
                        {formatLithuanianDateTime(scan.created_at)}
                      </Link>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      {scan.scan_type === 'light' ? 'Lengvas' : 'Gilus'}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${statusColors[scan.status] || ''}`}>
                        {statusLabels[scan.status] || scan.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {report ? (
                        <span className={`text-lg font-bold ${riskScoreColor(report.risk_score)}`}>
                          {report.risk_score ?? '—'}
                        </span>
                      ) : (
                        <span className="text-sm text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {report ? (
                        <div className="flex gap-1.5 text-xs">
                          {report.critical_count > 0 && (
                            <span className="text-red-600 font-medium">{report.critical_count} K</span>
                          )}
                          {report.high_count > 0 && (
                            <span className="text-orange-600 font-medium">{report.high_count} A</span>
                          )}
                          {report.medium_count > 0 && (
                            <span className="text-yellow-600 font-medium">{report.medium_count} V</span>
                          )}
                          {report.low_count > 0 && (
                            <span className="text-blue-600 font-medium">{report.low_count} Ž</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-sm text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      {scan.started_at && scan.completed_at
                        ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)} sek.`
                        : '—'}
                    </td>
                    <td className="px-6 py-4">
                      {scan.status === 'completed' ? (
                        <div className="flex items-center gap-2">
                          {report?.pdf_path && (
                            <Link
                              href={`/reports/${scan.id}`}
                              className="px-3 py-1.5 bg-gray-100 text-gray-700 text-xs font-medium rounded-md hover:bg-gray-200 whitespace-nowrap"
                            >
                              Peržiūrėti
                            </Link>
                          )}
                          <ReportDownloadButton
                            scanId={scan.id}
                            hasReport={!!report?.pdf_path}
                          />
                        </div>
                      ) : (
                        <span className="text-sm text-gray-400">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
