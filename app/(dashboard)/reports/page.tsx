import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { ReportDownloadButton } from '@/components/report-download-button';

export default async function ReportsPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data: profile } = await supabase
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

  const client = isSuperadmin ? createServiceRoleClient() : supabase;

  let reportsQuery = client
    .from('reports')
    .select('*, organizations(name)')
    .order('created_at', { ascending: false });
  if (!isSuperadmin) {
    reportsQuery = reportsQuery.eq('org_id', profile!.org_id!);
  }
  const { data: reports } = await reportsQuery;

  const riskColor = (score: number | null) => {
    if (score === null) return 'text-gray-400';
    if (score >= 70) return 'text-red-600';
    if (score >= 41) return 'text-yellow-600';
    return 'text-green-600';
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Ataskaitos</h1>

      {!reports || reports.length === 0 ? (
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <p className="text-gray-500">Ataskaitų dar nėra. Ataskaita bus sugeneruota po skenavimo.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {reports.map((report) => (
            <div key={report.id} className="bg-white rounded-lg shadow-md p-6">
              <div className="flex items-center justify-between">
                <div>
                  {isSuperadmin && (report as Record<string, unknown>).organizations ? (
                    <p className="text-xs font-semibold text-blue-600 mb-1">
                      {((report as Record<string, unknown>).organizations as { name: string }).name}
                    </p>
                  ) : null}
                  <p className="text-sm text-gray-500">
                    {new Date(report.created_at).toLocaleDateString('lt-LT')}
                  </p>
                  <div className="flex items-center space-x-4 mt-2">
                    <span className={`text-2xl font-bold ${riskColor(report.risk_score)}`}>
                      {report.risk_score ?? '—'}
                    </span>
                    <div className="text-sm text-gray-600">
                      <span className="text-red-600">{report.critical_count} kritiniai</span>{' · '}
                      <span className="text-orange-600">{report.high_count} aukšti</span>{' · '}
                      <span className="text-yellow-600">{report.medium_count} vidutiniai</span>{' · '}
                      <span className="text-blue-600">{report.low_count} žemi</span>
                    </div>
                  </div>
                </div>
                <ReportDownloadButton
                  scanId={report.scan_id}
                  hasReport={!!report.pdf_path}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
