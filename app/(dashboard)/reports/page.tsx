import { createServerSupabaseClient } from '@/lib/supabase/server';

export default async function ReportsPage() {
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

  const { data: reports } = await supabase
    .from('reports')
    .select('*')
    .eq('org_id', profile.org_id)
    .order('created_at', { ascending: false });

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
                {report.pdf_path && (
                  <a
                    href={`/api/reports?id=${report.id}`}
                    className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700"
                  >
                    Atsisiųsti PDF
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
