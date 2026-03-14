import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { ScanTriggerButton } from '@/components/scan-trigger-button';
import { FindingsList } from '@/components/findings-list';
import { RiskScoreBadge } from '@/components/risk-score-badge';
import { RiskTrendChart } from '@/components/risk-trend-chart';
import { DataEnrichment } from '@/components/data-enrichment';
import type { Finding } from '@/types/database';
import { formatLithuanianDateShort, formatLithuanianDateLong, formatLithuanianTime, formatLithuanianDate } from '@/lib/utils/date';

export default async function DashboardPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return null;

  // Use service role to read profile — superadmin has org_id=NULL which breaks RLS
  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  // Superadmin without org — redirect to admin dashboard
  if (profile?.role === 'superadmin' && !profile?.org_id) {
    redirect('/admin');
  }

  if (!profile?.org_id) {
    return (
      <div className="max-w-2xl mx-auto mt-8">
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <h1 className="text-2xl font-bold text-gray-900 mb-4">
            Sveiki atvykę į scanit.lt
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

  if (!org) {
    return (
      <div className="text-center py-12">
        <div className="bg-white rounded-lg shadow-md p-8 max-w-md mx-auto">
          <h2 className="text-xl font-bold text-gray-900 mb-2">Organizacija nerasta</h2>
          <p className="text-gray-600">
            Jūsų organizacijos duomenys nebuvo rasti. Kreipkitės į administratorių.
          </p>
        </div>
      </div>
    );
  }

  // Load latest scan
  const { data: scansArr } = await supabase
    .from('scans')
    .select('*')
    .eq('org_id', org.id)
    .order('created_at', { ascending: false })
    .limit(1);
  const latestScan = scansArr?.[0] ?? null;

  // Load latest report
  const { data: reportsArr } = await supabase
    .from('reports')
    .select('*')
    .eq('org_id', org.id)
    .order('created_at', { ascending: false })
    .limit(1);
  const latestReport = reportsArr?.[0] ?? null;

  // Load last 5 reports for trend chart
  const { data: trendReports } = await supabase
    .from('reports')
    .select('risk_score, created_at')
    .eq('org_id', org.id)
    .order('created_at', { ascending: true })
    .limit(5);

  const trendPoints = (trendReports ?? [])
    .filter((r) => r.risk_score !== null)
    .map((r) => ({
      date: formatLithuanianDateShort(r.created_at),
      score: r.risk_score as number,
    }));

  // Load findings for latest completed scan
  let findings: Finding[] = [];
  const findingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  if (latestScan && latestScan.status === 'completed') {
    const { data: scanFindings } = await supabase
      .from('findings')
      .select('*')
      .eq('scan_id', latestScan.id)
      .order('created_at', { ascending: true });

    if (scanFindings) {
      findings = scanFindings as Finding[];
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

  const isActive = latestScan && (latestScan.status === 'queued' || latestScan.status === 'running');

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <h1 className="text-2xl font-bold text-gray-900">Valdymo skydelis</h1>
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:space-x-4">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-500">{org.name}</span>
            <span className={`inline-block w-3 h-3 rounded-full ${org.verified ? 'bg-green-500' : 'bg-yellow-500'}`} aria-hidden="true" />
            <span className="text-xs text-gray-400">
              {org.verified ? 'Domenas patvirtintas' : 'Domenas nepatvirtintas'}
            </span>
          </div>
          <ScanTriggerButton orgVerified={org.verified} isAdmin={profile.role === 'admin' || profile.role === 'superadmin'} />
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

      {/* Active scan indicator */}
      {isActive && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 animate-pulse">
          <p className="text-sm text-blue-800">
            Skenavimas vykdomas... Būsena: {statusLabels[latestScan.status] || latestScan.status}.
            Puslapis automatiškai atsinaujins, kai skenavimas bus baigtas.
          </p>
        </div>
      )}

      {/* Top row: Risk Score + Last Scan + Finding Counts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Risk score with RAG circle */}
        <div className="bg-white rounded-lg shadow-md p-6 flex flex-col items-center">
          <h2 className="text-sm font-medium text-gray-500 mb-4">Rizikos balas</h2>
          <RiskScoreBadge score={latestReport?.risk_score ?? null} size="lg" />
        </div>

        {/* Last scan info */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-2">Paskutinis skenavimas</h2>
          {latestScan ? (
            <div>
              <p className="text-lg font-semibold text-gray-900">
                {formatLithuanianDateLong(latestScan.created_at)}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                {formatLithuanianTime(latestScan.created_at)}
              </p>
              <div className="mt-3">
                <span className={`inline-flex px-2.5 py-1 text-xs font-medium rounded-full ${
                  latestScan.status === 'completed' ? 'bg-green-100 text-green-800' :
                  latestScan.status === 'failed' ? 'bg-red-100 text-red-800' :
                  latestScan.status === 'running' ? 'bg-blue-100 text-blue-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {statusLabels[latestScan.status] || latestScan.status}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-gray-400 text-sm">Skenavimų dar nebuvo</p>
          )}
        </div>

        {/* Finding counts with color coding */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-3">Nustatyti trūkumai</h2>
          {findings.length > 0 ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Kritiniai</span>
                <span className={`text-lg font-bold ${findingCounts.critical > 0 ? 'text-red-600' : 'text-gray-300'}`}>
                  {findingCounts.critical}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Aukšti</span>
                <span className={`text-lg font-bold ${findingCounts.high > 0 ? 'text-orange-600' : 'text-gray-300'}`}>
                  {findingCounts.high}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Vidutiniai</span>
                <span className={`text-lg font-bold ${findingCounts.medium > 0 ? 'text-yellow-600' : 'text-gray-300'}`}>
                  {findingCounts.medium}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Žemi</span>
                <span className={`text-lg font-bold ${findingCounts.low > 0 ? 'text-blue-600' : 'text-gray-300'}`}>
                  {findingCounts.low}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-gray-400 text-sm">Nėra duomenų</p>
          )}
        </div>
      </div>

      {/* Risk trend chart */}
      <RiskTrendChart points={trendPoints} />

      {/* Data enrichment section — shown after domain verification */}
      {org.verified && profile.role === 'admin' && (
        <DataEnrichment
          orgId={org.id}
          domainVerified={org.verified}
          currentIpRanges={org.ip_ranges ?? []}
          currentEmails={org.employee_emails ?? []}
          currentSubdomains={org.subdomains ?? []}
        />
      )}

      {/* Findings list */}
      {latestScan && latestScan.status === 'completed' && (
        <div>
          <h2 className="text-lg font-bold text-gray-900 mb-4">
            Skenavimo rezultatai — {formatLithuanianDate(latestScan.created_at)}
          </h2>
          <FindingsList findings={findings} />
        </div>
      )}

      {/* Legal compliance note */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <p className="text-sm text-blue-800">
          Pagal Kibernetinio saugumo reikalavimų aprašo 45.8 punktą, organizacijos privalo
          atlikti pažeidžiamumų skenavimą ne rečiau kaip kartą per 6 mėnesius.
          scanit.lt atlieka skenavimą kas mėnesį — automatiškai viršijant įstatymo reikalavimą.
        </p>
      </div>
    </div>
  );
}
