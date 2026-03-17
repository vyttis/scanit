import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { ScanConfigPanel } from '@/components/scan-config-panel';
import { FindingsList } from '@/components/findings-list';
import { RiskScoreBadge } from '@/components/risk-score-badge';
import { RiskTrendChart } from '@/components/risk-trend-chart';
import type { Finding, PlanType } from '@/types/database';
import { formatLithuanianDateShort, formatLithuanianDateLong, formatLithuanianTime, formatLithuanianDate } from '@/lib/utils/date';
import { computeScanDelta, type ScanDelta } from '@/lib/utils/scan-delta';
import { countOverdue } from '@/lib/utils/sla';
import type { FindingSeverity } from '@/types/database';

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

  // Superadmin — always redirect to admin dashboard (they manage all orgs)
  if (profile?.role === 'superadmin') {
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

  // Fetch finding statuses for remediation tracking
  const findingStatuses: Record<string, { status: import('@/types/database').FindingStatusType; note: string | null }> = {};
  if (findings.length > 0) {
    const { data: statuses } = await supabase
      .from('finding_status')
      .select('finding_id, status, note')
      .eq('org_id', org.id);

    if (statuses) {
      for (const s of statuses) {
        findingStatuses[s.finding_id] = { status: s.status, note: s.note };
      }
    }
  }

  // Compute scan delta (compare with previous scan)
  let scanDelta: ScanDelta | null = null;
  if (latestScan && latestScan.status === 'completed' && findings.length > 0) {
    const { data: prevScansArr } = await supabase
      .from('scans')
      .select('id')
      .eq('org_id', org.id)
      .eq('status', 'completed')
      .order('created_at', { ascending: false })
      .limit(2);

    const prevScan = prevScansArr?.[1]; // second most recent completed scan
    if (prevScan) {
      const { data: prevFindings } = await supabase
        .from('findings')
        .select('*')
        .eq('scan_id', prevScan.id);

      if (prevFindings && prevFindings.length > 0) {
        scanDelta = computeScanDelta(findings, prevFindings as Finding[]);
      }
    }
  }

  // Compute SLA overdue stats
  const overdueStats = findings.length > 0
    ? countOverdue(
        findings.map((f) => ({
          severity: f.severity as FindingSeverity,
          created_at: f.created_at,
          status: findingStatuses[f.id]?.status || 'open',
        }))
      )
    : { overdue: 0, expiringSoon: 0 };

  // Fetch benchmark data (client's sector ranking)
  let benchmarkData: { available: boolean; percentile?: number; sector_avg?: number; user_score?: number; sector_count?: number; sector?: string } | null = null;
  try {
    const benchRes = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || ''}/api/benchmark`, {
      headers: { cookie: (await import('next/headers')).cookies().toString() },
      cache: 'no-store',
    });
    if (benchRes.ok) {
      benchmarkData = await benchRes.json();
    }
  } catch { /* silent — benchmark is optional */ }

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
          <ScanConfigPanel
            orgVerified={org.verified}
            isAdmin={profile.role === 'admin' || profile.role === 'superadmin'}
            domain={org.domain}
            plan={((org as Record<string, unknown>).plan as PlanType) || 'basic'}
          />
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

      {/* Overdue + Benchmark row */}
      {(overdueStats.overdue > 0 || overdueStats.expiringSoon > 0 || (benchmarkData?.available)) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Overdue findings widget */}
          {(overdueStats.overdue > 0 || overdueStats.expiringSoon > 0) && (
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-sm font-medium text-gray-500 mb-4">SLA būsena</h2>
              <div className="space-y-3">
                {overdueStats.overdue > 0 && (
                  <div className="flex items-center gap-3 p-3 bg-red-50 rounded-lg">
                    <span className="text-2xl font-bold text-red-600">{overdueStats.overdue}</span>
                    <div>
                      <p className="text-sm font-medium text-red-800">Vėluojantys trūkumai</p>
                      <p className="text-xs text-red-600">SLA terminas praėjęs — būtina skubiai reaguoti</p>
                    </div>
                  </div>
                )}
                {overdueStats.expiringSoon > 0 && (
                  <div className="flex items-center gap-3 p-3 bg-yellow-50 rounded-lg">
                    <span className="text-2xl font-bold text-yellow-600">{overdueStats.expiringSoon}</span>
                    <div>
                      <p className="text-sm font-medium text-yellow-800">Artėjantys terminai</p>
                      <p className="text-xs text-yellow-600">SLA terminas baigiasi per 3 dienas</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Benchmark widget */}
          {benchmarkData?.available && (
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-sm font-medium text-gray-500 mb-4">Sektoriaus palyginimas</h2>
              <div className="text-center">
                <p className="text-4xl font-bold text-blue-600">{benchmarkData.percentile}%</p>
                <p className="text-sm text-gray-600 mt-2">
                  Jūsų organizacija geriau nei <strong>{benchmarkData.percentile}%</strong> sektoriaus organizacijų
                </p>
                <div className="mt-4 flex items-center justify-center gap-6 text-sm">
                  <div>
                    <p className="text-gray-500">Jūsų balas</p>
                    <p className="text-lg font-semibold text-gray-900">{benchmarkData.user_score}</p>
                  </div>
                  <div className="h-8 w-px bg-gray-200" />
                  <div>
                    <p className="text-gray-500">Sektoriaus vidurkis</p>
                    <p className="text-lg font-semibold text-gray-900">{benchmarkData.sector_avg}</p>
                  </div>
                </div>
                <p className="text-xs text-gray-400 mt-3">
                  Palyginimas su {benchmarkData.sector_count} organizacijomis sektoriuje
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scan delta — comparison with previous scan */}
      {scanDelta && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-4">Palyginimas su praėjusiu skaitymu</h2>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div className="p-4 bg-red-50 rounded-lg">
              <p className="text-2xl font-bold text-red-600">{scanDelta.newCount}</p>
              <p className="text-sm text-red-700 mt-1">Nauji trūkumai</p>
            </div>
            <div className="p-4 bg-green-50 rounded-lg">
              <p className="text-2xl font-bold text-green-600">{scanDelta.resolvedCount}</p>
              <p className="text-sm text-green-700 mt-1">Išspręsti</p>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg">
              <p className="text-2xl font-bold text-gray-600">{scanDelta.persistentCount}</p>
              <p className="text-sm text-gray-600 mt-1">Išlikę</p>
            </div>
          </div>
          {scanDelta.newCount > 0 && (
            <div className="mt-4 border-t border-gray-100 pt-4">
              <h3 className="text-xs font-semibold text-red-700 uppercase tracking-wide mb-2">Nauji trūkumai nuo praėjusio skenavimo</h3>
              <ul className="space-y-1">
                {scanDelta.newFindings.slice(0, 5).map((f) => (
                  <li key={f.id} className="flex items-center gap-2 text-sm">
                    <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${
                      f.severity === 'critical' ? 'bg-red-600' :
                      f.severity === 'high' ? 'bg-orange-600' :
                      f.severity === 'medium' ? 'bg-yellow-600' : 'bg-blue-600'
                    }`} />
                    <span className="text-gray-700 truncate">{f.title_lt}</span>
                  </li>
                ))}
                {scanDelta.newCount > 5 && (
                  <li className="text-xs text-gray-500">ir dar {scanDelta.newCount - 5}...</li>
                )}
              </ul>
            </div>
          )}
          {scanDelta.resolvedCount > 0 && (
            <div className="mt-4 border-t border-gray-100 pt-4">
              <h3 className="text-xs font-semibold text-green-700 uppercase tracking-wide mb-2">Išspręsti nuo praėjusio skenavimo</h3>
              <ul className="space-y-1">
                {scanDelta.resolvedFindings.slice(0, 5).map((f) => (
                  <li key={f.id} className="flex items-center gap-2 text-sm">
                    <span className="inline-block w-2 h-2 rounded-full flex-shrink-0 bg-green-500" />
                    <span className="text-gray-500 line-through truncate">{f.title_lt}</span>
                  </li>
                ))}
                {scanDelta.resolvedCount > 5 && (
                  <li className="text-xs text-gray-500">ir dar {scanDelta.resolvedCount - 5}...</li>
                )}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Plan upsell card — shown only to basic plan users */}
      {((org as Record<string, unknown>).plan || 'basic') !== 'professional' && profile.role === 'admin' && (
        <div className="bg-gradient-to-r from-slate-800 to-slate-900 rounded-lg shadow-md p-6 text-white">
          <h3 className="text-base font-bold mb-2">
            Padidinkite skenavimo tikslumą
          </h3>
          <p className="text-sm text-slate-300 mb-3">
            Šiuo metu tikrinama: tik domenas
          </p>
          <p className="text-sm text-slate-300 mb-4">
            Profesionalaus plano vartotojai taip pat gali tikrinti:
          </p>
          <ul className="space-y-1.5 text-sm text-slate-300 mb-5">
            <li className="flex items-center gap-2">
              <span className="text-slate-500">→</span> IP adresų infrastruktūrą
            </li>
            <li className="flex items-center gap-2">
              <span className="text-slate-500">→</span> Kiekvieną subdomeną atskirai
            </li>
            <li className="flex items-center gap-2">
              <span className="text-slate-500">→</span> Darbuotojų el. paštų nutekėjimus
            </li>
          </ul>
          <Link
            href="/settings#plan"
            className="inline-block px-5 py-2.5 bg-blue-600 text-white text-sm font-semibold rounded-lg hover:bg-blue-700 transition-colors"
          >
            Sužinoti daugiau apie Profesionalų planą
          </Link>
        </div>
      )}

      {/* Findings list */}
      {latestScan && latestScan.status === 'completed' && (
        <div>
          <h2 className="text-lg font-bold text-gray-900 mb-4">
            Skenavimo rezultatai — {formatLithuanianDate(latestScan.created_at)}
          </h2>
          <FindingsList
            findings={findings}
            findingStatuses={findingStatuses}
            isAdmin={profile.role === 'admin'}
            scanId={latestScan.id}
          />
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
