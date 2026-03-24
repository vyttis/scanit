import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { ReportDownloadButton } from '@/components/report-download-button';
import { formatLithuanianDateTime } from '@/lib/utils/date';

export default async function ScansPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect('/login');

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
    .order('created_at', { ascending: false })
    .limit(200);
  if (!isSuperadmin) {
    scansQuery = scansQuery.eq('org_id', profile!.org_id!);
  }

  let reportsQuery = client
    .from('reports')
    .select('id, scan_id, risk_score, critical_count, high_count, medium_count, low_count, pdf_path')
    .limit(200);
  if (!isSuperadmin) {
    reportsQuery = reportsQuery.eq('org_id', profile!.org_id!);
  }

  // Run scans and reports queries in parallel
  const [{ data: scans }, { data: reports }] = await Promise.all([scansQuery, reportsQuery]);

  // Fetch finding counts only for scans that don't have a report yet
  const reportScanIds = new Set((reports ?? []).map(r => r.scan_id));
  const scansWithoutReport = (scans ?? []).filter(s => !reportScanIds.has(s.id)).map(s => s.id);

  let allFindings: { scan_id: string; severity: string }[] | null = null;
  if (scansWithoutReport.length > 0) {
    let findingsQuery = client
      .from('findings')
      .select('scan_id, severity')
      .in('scan_id', scansWithoutReport)
      .limit(5000);
    if (!isSuperadmin) {
      findingsQuery = findingsQuery.eq('org_id', profile!.org_id!);
    }
    const { data } = await findingsQuery;
    allFindings = data;
  }

  const reportByScanId = new Map(
    (reports ?? []).map((r) => [r.scan_id, r]),
  );

  // Build finding counts per scan from findings table
  const findingCountsByScanId = new Map<string, { critical: number; high: number; medium: number; low: number }>();
  for (const f of (allFindings ?? [])) {
    const counts = findingCountsByScanId.get(f.scan_id) || { critical: 0, high: 0, medium: 0, low: 0 };
    if (f.severity === 'critical') counts.critical++;
    else if (f.severity === 'high') counts.high++;
    else if (f.severity === 'medium') counts.medium++;
    else if (f.severity === 'low') counts.low++;
    findingCountsByScanId.set(f.scan_id, counts);
  }

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

  function riskScoreColor(score: number | null | undefined): string {
    if (score === null || score === undefined) return 'text-gray-400';
    if (score >= 70) return 'text-red-600';
    if (score >= 41) return 'text-yellow-600';
    if (score > 0) return 'text-green-600';
    // score === 0 — still show as red (0 risk means no issues, but if explicitly 0 from report it's fine)
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
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Veiksmai</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {scans.map((scan) => {
                const report = reportByScanId.get(scan.id);
                const counts = report
                  ? { critical: report.critical_count ?? 0, high: report.high_count ?? 0, medium: report.medium_count ?? 0, low: report.low_count ?? 0 }
                  : findingCountsByScanId.get(scan.id);
                const hasAnyFindings = counts && (counts.critical > 0 || counts.high > 0 || counts.medium > 0 || counts.low > 0);

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
                      {formatLithuanianDateTime(scan.created_at)}
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
                      {report?.risk_score !== null && report?.risk_score !== undefined ? (
                        <span className={`text-lg font-bold ${riskScoreColor(report.risk_score)}`}>
                          {report.risk_score}
                        </span>
                      ) : (
                        <span className="text-sm text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {hasAnyFindings ? (
                        <div className="flex gap-1.5 text-xs">
                          {counts!.critical > 0 && (
                            <span className="text-red-600 font-medium">{counts!.critical}K</span>
                          )}
                          {counts!.high > 0 && (
                            <span className="text-orange-600 font-medium">{counts!.high}A</span>
                          )}
                          {counts!.medium > 0 && (
                            <span className="text-yellow-600 font-medium">{counts!.medium}V</span>
                          )}
                          {counts!.low > 0 && (
                            <span className="text-blue-600 font-medium">{counts!.low}Ž</span>
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
                      {scan.status === 'completed' && (
                        <div className="flex items-center gap-2">
                          <Link
                            href={`/scans/${scan.id}`}
                            className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 whitespace-nowrap"
                          >
                            Rezultatai
                          </Link>
                          {report?.pdf_path ? (
                            <>
                              <Link
                                href={`/reports/${scan.id}`}
                                className="px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-md hover:bg-blue-700 whitespace-nowrap"
                              >
                                Peržiūrėti ataskaitą
                              </Link>
                              <ReportDownloadButton scanId={scan.id} hasReport={true} />
                            </>
                          ) : (
                            <ReportDownloadButton scanId={scan.id} hasReport={false} />
                          )}
                        </div>
                      )}
                      {scan.status === 'running' && (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 rounded-md">
                          <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                          Vykdoma...
                        </span>
                      )}
                      {scan.status === 'queued' && (
                        <span className="inline-flex px-3 py-1.5 text-xs font-medium text-gray-500 bg-gray-50 rounded-md">
                          Laukiama...
                        </span>
                      )}
                      {scan.status === 'failed' && (
                        <div className="flex items-center gap-2">
                          <span className="inline-flex px-2 py-1 text-xs font-medium text-red-700 bg-red-50 rounded-full">
                            Nepavyko
                          </span>
                          <Link
                            href={`/scans/${scan.id}`}
                            className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 whitespace-nowrap"
                          >
                            Detalės
                          </Link>
                        </div>
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
