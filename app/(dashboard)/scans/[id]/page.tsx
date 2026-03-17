import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { FindingsList } from '@/components/findings-list';
import { RiskScoreBadge } from '@/components/risk-score-badge';
import { ReportDownloadButton } from '@/components/report-download-button';
import { formatLithuanianDateTime } from '@/lib/utils/date';
import type { Finding } from '@/types/database';

const MODULE_LABELS: Record<string, string> = {
  shodan: 'Shodan',
  hibp: 'HaveIBeenPwned',
  ssl: 'SSL Labs',
  mxtoolbox: 'El. pašto sauga (DNS)',
  securitytrails: 'SecurityTrails',
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  urlscan: 'URLScan',
};

const ALL_MODULES = ['shodan', 'hibp', 'ssl', 'mxtoolbox', 'securitytrails', 'virustotal', 'abuseipdb', 'urlscan'];

interface ScannerError {
  module: string;
  error: string;
}

export default async function ScanDetailPage({ params }: { params: { id: string } }) {
  const scanId = params.id;

  // Validate UUID format
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scanId)) {
    notFound();
  }

  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  const isSuperadmin = profile?.role === 'superadmin';

  // Fetch scan
  const queryClient = isSuperadmin ? serviceClient : supabase;
  const { data: scan } = await queryClient
    .from('scans')
    .select('*, organizations(name, domain)')
    .eq('id', scanId)
    .single();

  if (!scan) {
    notFound();
  }

  // For non-superadmin, verify org ownership
  if (!isSuperadmin && profile?.org_id && scan.org_id !== profile.org_id) {
    notFound();
  }

  // Fetch findings
  const findingsClient = isSuperadmin ? serviceClient : supabase;
  const { data: findingsData } = await findingsClient
    .from('findings')
    .select('*')
    .eq('scan_id', scanId)
    .order('created_at', { ascending: true });

  const findings: Finding[] = (findingsData ?? []) as Finding[];

  // Fetch report (if exists)
  const { data: report } = await queryClient
    .from('reports')
    .select('id, risk_score, critical_count, high_count, medium_count, low_count, pdf_path')
    .eq('scan_id', scanId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  // Count findings by severity
  const findingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    findingCounts[f.severity as keyof typeof findingCounts]++;
  });

  // Calculate risk score from findings if report doesn't have one
  const SEVERITY_WEIGHTS: Record<string, number> = { critical: 25, high: 15, medium: 5, low: 1, info: 0 };
  const calculatedRiskScore = Math.min(100, findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0,
  ));
  const displayRiskScore = report?.risk_score ?? (findings.length > 0 ? calculatedRiskScore : null);

  // Parse scanner errors
  const scannerErrors: ScannerError[] = Array.isArray(scan.scanner_errors) ? scan.scanner_errors : [];
  const failedModules = new Set(scannerErrors.map((e: ScannerError) => e.module));

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

  const orgName = (scan as Record<string, unknown>).organizations
    ? ((scan as Record<string, unknown>).organizations as { name: string; domain: string }).name
    : '';
  const orgDomain = (scan as Record<string, unknown>).organizations
    ? ((scan as Record<string, unknown>).organizations as { name: string; domain: string }).domain
    : '';

  const duration = scan.started_at && scan.completed_at
    ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
    : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link href="/scans" className="text-sm text-blue-600 hover:text-blue-800 mb-2 inline-block">
            &larr; Grįžti į skenavimų istoriją
          </Link>
          <h1 className="text-2xl font-bold text-gray-900">Skenavimo rezultatai</h1>
          {orgName && (
            <p className="text-sm text-gray-500 mt-1">{orgName} &middot; {orgDomain}</p>
          )}
        </div>
        {scan.status === 'completed' && (
          <div className="flex items-center gap-3">
            {report?.pdf_path && (
              <Link
                href={`/reports/${scan.id}`}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm font-semibold rounded-lg hover:bg-blue-700 shadow-sm transition-colors whitespace-nowrap"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Peržiūrėti ataskaitą
              </Link>
            )}
            <ReportDownloadButton scanId={scan.id} hasReport={!!report?.pdf_path} />
          </div>
        )}
      </div>

      {/* Scan metadata */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase">Data</span>
            <p className="text-sm text-gray-900 mt-1">{formatLithuanianDateTime(scan.created_at)}</p>
          </div>
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase">Būsena</span>
            <p className="mt-1">
              <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${statusColors[scan.status] || ''}`}>
                {statusLabels[scan.status] || scan.status}
              </span>
            </p>
          </div>
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase">Trukmė</span>
            <p className="text-sm text-gray-900 mt-1">{duration !== null ? `${duration} sek.` : '—'}</p>
          </div>
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase">Tipas</span>
            <p className="text-sm text-gray-900 mt-1">{scan.scan_type === 'light' ? 'Lengvas' : 'Gilus'}</p>
          </div>
        </div>
      </div>

      {/* Scan scope */}
      {scan.scan_scope && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-sm font-medium text-gray-500 mb-3">Skenavimo apimtis</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase">Domenas</span>
              <p className="text-gray-900 mt-1">{orgDomain || '—'}</p>
            </div>
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase">IP rangai</span>
              <p className="text-gray-900 mt-1">
                {(scan.scan_scope as Record<string, unknown>).ip_ranges
                  ? (((scan.scan_scope as Record<string, unknown>).ip_ranges as string[]).join(', '))
                  : 'nenurodyti'}
              </p>
            </div>
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase">Subdomenai</span>
              <p className="text-gray-900 mt-1">
                {(scan.scan_scope as Record<string, unknown>).subdomains
                  ? `${((scan.scan_scope as Record<string, unknown>).subdomains as string[]).length} subdomenų`
                  : 'nenurodyti'}
              </p>
            </div>
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase">El. paštai</span>
              <p className="text-gray-900 mt-1">
                {(scan.scan_scope as Record<string, unknown>).email_count
                  ? `${(scan.scan_scope as Record<string, unknown>).email_count} el. paštų (neišsaugoma)`
                  : 'nenurodyti'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Risk score + finding counts */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg shadow-md p-6 flex flex-col items-center">
            <h2 className="text-sm font-medium text-gray-500 mb-4">Rizikos balas</h2>
            <RiskScoreBadge score={displayRiskScore} size="lg" />
          </div>
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Nustatyti trūkumai</h2>
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
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Informaciniai</span>
                <span className={`text-lg font-bold ${findingCounts.info > 0 ? 'text-gray-600' : 'text-gray-300'}`}>
                  {findingCounts.info}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scanner modules status */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-sm font-medium text-gray-500 mb-3">Skenavimo moduliai</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {ALL_MODULES.map((mod) => {
            const hasFailed = failedModules.has(mod);
            return (
              <div
                key={mod}
                className={`flex items-center gap-2 p-2 rounded-md ${
                  hasFailed ? 'bg-red-50' : 'bg-green-50'
                }`}
                title={hasFailed ? 'Modulis nepavyko — bandykite dar kartą' : 'Modulis sėkmingai įvykdytas'}
              >
                {hasFailed ? (
                  <svg className="w-4 h-4 text-red-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                ) : (
                  <svg className="w-4 h-4 text-green-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                )}
                <span className={`text-xs font-medium ${hasFailed ? 'text-red-700' : 'text-green-700'}`}>
                  {MODULE_LABELS[mod] || mod}
                </span>
              </div>
            );
          })}
        </div>
        {scannerErrors.length > 0 && (
          <div className="mt-4 bg-yellow-50 border border-yellow-200 rounded-lg p-3">
            <p className="text-xs font-medium text-yellow-800 mb-2">
              {scannerErrors.length} modulis(-iai) nepavyko:
            </p>
            {scannerErrors.map((err: ScannerError, i: number) => (
              <p key={i} className="text-xs text-yellow-700">
                <span className="font-medium">{MODULE_LABELS[err.module] || err.module}</span>: Nepavyko gauti duomenų. Bandykite pakartoti skenavimą.
              </p>
            ))}
          </div>
        )}
      </div>

      {/* Findings list */}
      {scan.status === 'completed' && (
        <div>
          <h2 className="text-lg font-bold text-gray-900 mb-4">Nustatyti trūkumai</h2>
          <FindingsList
            findings={findings}
            isAdmin={profile?.role === 'admin' || isSuperadmin}
            scanId={scan.id}
          />
        </div>
      )}

      {/* Failed scan info */}
      {scan.status === 'failed' && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <p className="text-red-800 font-medium">Skenavimas nepavyko</p>
          <p className="text-sm text-red-600 mt-2">
            Patikrinkite skenavimo modulių būseną aukščiau. Dažniausia priežastis — nesukonfigūruoti API raktai.
          </p>
        </div>
      )}
    </div>
  );
}
