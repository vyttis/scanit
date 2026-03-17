import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import type { Finding } from '@/types/database';
import { evaluateCompliance, calculateCompliancePercentage, type ComplianceStatus } from '@/lib/utils/compliance-mapping';
import { formatLithuanianDate } from '@/lib/utils/date';

const STATUS_CONFIG: Record<ComplianceStatus, { label: string; color: string; bg: string; icon: string }> = {
  pass: { label: 'Atitinka', color: 'text-green-700', bg: 'bg-green-100', icon: '✓' },
  partial: { label: 'Dalinis', color: 'text-yellow-700', bg: 'bg-yellow-100', icon: '!' },
  fail: { label: 'Neatitinka', color: 'text-red-700', bg: 'bg-red-100', icon: '✗' },
  not_checked: { label: 'Netikrinta', color: 'text-gray-500', bg: 'bg-gray-100', icon: '—' },
};

export default async function CompliancePage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  const serviceClient = createServiceRoleClient();
  const { data: profile } = await serviceClient
    .from('profiles')
    .select('org_id, role')
    .eq('id', user.id)
    .single();

  if (profile?.role === 'superadmin') redirect('/admin');
  if (!profile?.org_id) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Pirmiausia užregistruokite organizaciją nustatymuose.</p>
      </div>
    );
  }

  // Load org
  const { data: org } = await supabase
    .from('organizations')
    .select('name, domain')
    .eq('id', profile.org_id)
    .single();

  // Load latest completed scan findings
  const { data: scansArr } = await supabase
    .from('scans')
    .select('id, created_at')
    .eq('org_id', profile.org_id)
    .eq('status', 'completed')
    .order('created_at', { ascending: false })
    .limit(1);

  const latestScan = scansArr?.[0];
  let findings: Finding[] = [];
  if (latestScan) {
    const { data: scanFindings } = await supabase
      .from('findings')
      .select('*')
      .eq('scan_id', latestScan.id);
    findings = (scanFindings ?? []) as Finding[];
  }

  const results = evaluateCompliance(findings);
  const compliancePercent = calculateCompliancePercentage(results);

  // RAG color for overall compliance
  let overallColor = 'text-green-600';
  let overallBg = 'border-green-500';
  if (compliancePercent < 50) {
    overallColor = 'text-red-600';
    overallBg = 'border-red-500';
  } else if (compliancePercent < 80) {
    overallColor = 'text-yellow-600';
    overallBg = 'border-yellow-500';
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">KSĮ atitikties skydelis</h1>
          {org && (
            <p className="text-sm text-gray-500 mt-1">{org.name} · {org.domain}</p>
          )}
        </div>
        {latestScan && (
          <p className="text-sm text-gray-400">
            Paskutinis skenavimas: {formatLithuanianDate(latestScan.created_at)}
          </p>
        )}
      </div>

      {/* Overall compliance score */}
      <div className="bg-white rounded-lg shadow-md p-8 text-center">
        <h2 className="text-sm font-medium text-gray-500 mb-4">Bendra KSĮ atitiktis</h2>
        <div className={`inline-flex items-center justify-center w-28 h-28 rounded-full border-8 ${overallBg}`}>
          <span className={`text-3xl font-bold ${overallColor}`}>{compliancePercent}%</span>
        </div>
        <p className="text-sm text-gray-500 mt-4">
          Vertinimas pagal Kibernetinio saugumo įstatymo 11 straipsnio 2 dalies reikalavimus
        </p>
      </div>

      {/* Compliance matrix */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">KSĮ straipsnių atitikties matrica</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">KSĮ straipsnis</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reikalavimas</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Būsena</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trūkumų sk.</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Blogiausias lygis</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {results.map((result) => {
                const config = STATUS_CONFIG[result.status];
                const severityLabels: Record<string, string> = {
                  critical: 'Kritinis',
                  high: 'Aukštas',
                  medium: 'Vidutinis',
                  low: 'Žemas',
                };
                return (
                  <tr key={result.article.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 whitespace-nowrap">
                      {result.article.id}
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-sm font-medium text-gray-900">{result.article.title}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{result.article.citation}</p>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold ${config.bg} ${config.color}`}>
                        <span aria-hidden="true">{config.icon}</span>
                        {config.label}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {result.findingCount > 0 ? result.findingCount : '—'}
                    </td>
                    <td className="px-6 py-4 text-sm">
                      {result.worstSeverity ? (
                        <span className={`font-medium ${
                          result.worstSeverity === 'critical' ? 'text-red-600' :
                          result.worstSeverity === 'high' ? 'text-orange-600' :
                          result.worstSeverity === 'medium' ? 'text-yellow-600' : 'text-blue-600'
                        }`}>
                          {severityLabels[result.worstSeverity] || result.worstSeverity}
                        </span>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Legal reference */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <p className="text-sm text-blue-800">
          Ši atitikties matrica parengta vadovaujantis Kibernetinio saugumo įstatymo (2024 m. spalio 3 d. Nr. XIV-2960)
          11 straipsnio 2 dalies reikalavimais ir gali būti pateikta NKSC kaip atitikties įrodymas.
        </p>
      </div>

      {!latestScan && (
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <p className="text-gray-500 mb-4">Atitikties vertinimas bus galimas atlikus pirmąjį skenavimą.</p>
          <Link href="/dashboard" className="text-blue-600 hover:text-blue-800 font-medium text-sm">
            Grįžti į valdymo skydelį
          </Link>
        </div>
      )}
    </div>
  );
}
