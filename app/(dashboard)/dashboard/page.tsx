import { createServerSupabaseClient } from '@/lib/supabase/server';
import Link from 'next/link';

export default async function DashboardPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return null;

  const { data: profile } = await supabase
    .from('profiles')
    .select('org_id')
    .eq('id', user.id)
    .single();

  // If user has no organization, prompt to set one up
  if (!profile?.org_id) {
    return (
      <div className="max-w-2xl mx-auto mt-8">
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <h1 className="text-2xl font-bold text-gray-900 mb-4">
            Sveiki atvykę į pentester.lt
          </h1>
          <p className="text-gray-600 mb-6">
            Norėdami pradėti naudotis platforma, pirmiausia turite užregistruoti
            savo organizaciją ir patvirtinti domeno nuosavybę.
          </p>
          <Link
            href="/settings"
            className="inline-block px-6 py-3 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700"
          >
            Registruoti organizaciją
          </Link>
        </div>
      </div>
    );
  }

  // Load organization data
  const { data: org } = await supabase
    .from('organizations')
    .select('*')
    .eq('id', profile.org_id)
    .single();

  if (!org) return null;

  // Load latest scan
  const { data: latestScan } = await supabase
    .from('scans')
    .select('*')
    .eq('org_id', org.id)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  // Load latest report
  const { data: latestReport } = await supabase
    .from('reports')
    .select('*')
    .eq('org_id', org.id)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  // Load finding counts by severity for latest scan
  let findingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  if (latestScan) {
    const { data: findings } = await supabase
      .from('findings')
      .select('severity')
      .eq('scan_id', latestScan.id);

    if (findings) {
      findings.forEach((f) => {
        findingCounts[f.severity as keyof typeof findingCounts]++;
      });
    }
  }

  const statusLabels: Record<string, string> = {
    queued: 'Laukiama eilėje',
    running: 'Vykdomas',
    completed: 'Baigtas',
    failed: 'Nepavyko',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Valdymo skydelis</h1>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500">{org.name}</span>
          <span className={`inline-block w-3 h-3 rounded-full ${org.verified ? 'bg-green-500' : 'bg-yellow-500'}`} />
          <span className="text-xs text-gray-400">
            {org.verified ? 'Domenas patvirtintas' : 'Domenas nepatvirtintas'}
          </span>
        </div>
      </div>

      {!org.verified && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <p className="text-sm text-yellow-800">
            Jūsų domenas dar nepatvirtintas. Skenavimas galimas tik patvirtinus domeno nuosavybę.{' '}
            <Link href="/settings" className="font-medium underline">
              Patvirtinti domeną
            </Link>
          </p>
        </div>
      )}

      {/* Risk score card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-2">Rizikos balas</h2>
          {latestReport ? (
            <div className="flex items-center space-x-3">
              <span className={`text-4xl font-bold ${
                (latestReport.risk_score ?? 0) >= 70 ? 'text-red-600' :
                (latestReport.risk_score ?? 0) >= 40 ? 'text-yellow-600' :
                'text-green-600'
              }`}>
                {latestReport.risk_score ?? '—'}
              </span>
              <span className="text-sm text-gray-500">/ 100</span>
            </div>
          ) : (
            <p className="text-gray-400 text-sm">Nėra duomenų</p>
          )}
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-2">Paskutinis skenavimas</h2>
          {latestScan ? (
            <div>
              <p className="text-sm text-gray-900">
                {new Date(latestScan.created_at).toLocaleDateString('lt-LT')}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Būsena: {statusLabels[latestScan.status] || latestScan.status}
              </p>
            </div>
          ) : (
            <p className="text-gray-400 text-sm">Skenavimų dar nebuvo</p>
          )}
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-2">Nustatyti trūkumai</h2>
          {latestScan ? (
            <div className="flex space-x-3 text-sm">
              <span className="text-red-600 font-medium">{findingCounts.critical} kritiniai</span>
              <span className="text-orange-600 font-medium">{findingCounts.high} aukšti</span>
              <span className="text-yellow-600 font-medium">{findingCounts.medium} vidutiniai</span>
              <span className="text-blue-600 font-medium">{findingCounts.low} žemi</span>
            </div>
          ) : (
            <p className="text-gray-400 text-sm">Nėra duomenų</p>
          )}
        </div>
      </div>

      {/* Legal compliance note */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <p className="text-sm text-blue-800">
          Pagal Kibernetinio saugumo reikalavimų aprašo 45.8 punktą, organizacijos privalo
          atlikti pažeidžiamumų skenavimą ne rečiau kaip kartą per 6 mėnesius.
          pentester.lt atlieka skenavimą kas mėnesį — automatiškai viršijant įstatymo reikalavimą.
        </p>
      </div>
    </div>
  );
}
