import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import { AdminNav } from '@/components/admin-nav';

const ACTION_LABELS: Record<string, string> = {
  scan_triggered: 'Skenavimas paleistas',
  report_generated: 'Ataskaita sugeneruota',
  report_downloaded: 'Ataskaita atsisiųsta',
  login: 'Prisijungimas',
  login_failed: 'Nesėkmingas prisijungimas',
  domain_verified: 'Domenas patvirtintas',
  org_registered: 'Organizacija užregistruota',
  email_updated: 'El. paštas atnaujintas',
  user_approved: 'Vartotojas patvirtintas',
  user_rejected: 'Vartotojas atmestas',
};

function KpiCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
}) {
  return (
    <div className="bg-white rounded-lg shadow p-6 flex items-start space-x-4">
      <div className="flex-shrink-0 w-10 h-10 bg-blue-50 rounded-lg flex items-center justify-center text-blue-600">
        {icon}
      </div>
      <div>
        <p className="text-sm font-medium text-gray-500">{label}</p>
        <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
      </div>
    </div>
  );
}

function BarChart({
  title,
  data,
  color = 'bg-blue-500',
}: {
  title: string;
  data: { label: string; value: number }[];
  color?: string;
}) {
  const maxValue = Math.max(...data.map((d) => d.value), 1);

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">{title}</h3>
      <div className="flex items-end space-x-3 h-48">
        {data.map((item) => (
          <div key={item.label} className="flex-1 flex flex-col items-center justify-end h-full">
            <span className="text-xs font-medium text-gray-700 mb-1">{item.value}</span>
            <div
              className={`w-full rounded-t ${color} transition-all`}
              style={{
                height: `${(item.value / maxValue) * 100}%`,
                minHeight: item.value > 0 ? '4px' : '0px',
              }}
            />
            <span className="text-xs text-gray-500 mt-2 truncate w-full text-center">
              {item.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function RiskDistributionChart({
  data,
}: {
  data: { label: string; value: number; color: string }[];
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Rizikos pasiskirstymas</h3>
      <div className="space-y-4">
        {data.map((item) => (
          <div key={item.label}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-gray-700">{item.label}</span>
              <span className="text-sm font-semibold text-gray-900">{item.value}</span>
            </div>
            <div className="w-full bg-gray-100 rounded-full h-4">
              <div
                className={`${item.color} h-4 rounded-full transition-all`}
                style={{ width: `${(item.value / total) * 100}%`, minWidth: item.value > 0 ? '8px' : '0px' }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default async function AdminDashboardPage() {
  const supabase = createServerSupabaseClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    redirect('/login');
  }

  // Use service role client — superadmin has org_id=NULL which breaks RLS
  const serviceClient = createServiceRoleClient();

  const { data: profile } = await serviceClient
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  if (profile?.role !== 'superadmin') {
    redirect('/dashboard');
  }

  // KPI queries in parallel
  const now = new Date();
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const [
    orgsResult,
    usersResult,
    pendingResult,
    scansThisMonthResult,
    reportsThisMonthResult,
    latestReportsResult,
    auditLogResult,
  ] = await Promise.all([
    serviceClient.from('organizations').select('id', { count: 'exact', head: true }),
    serviceClient.from('profiles').select('id', { count: 'exact', head: true }),
    serviceClient.from('profiles').select('id', { count: 'exact', head: true }).eq('status', 'pending'),
    serviceClient.from('scans').select('id', { count: 'exact', head: true }).gte('created_at', startOfMonth),
    serviceClient.from('reports').select('id', { count: 'exact', head: true }).gte('created_at', startOfMonth),
    serviceClient.from('reports').select('risk_score, org_id').order('created_at', { ascending: false }),
    serviceClient
      .from('audit_log')
      .select('id, action, created_at, user_id, org_id')
      .order('created_at', { ascending: false })
      .limit(20),
  ]);

  const totalOrgs = orgsResult.count ?? 0;
  const totalUsers = usersResult.count ?? 0;
  const pendingUsers = pendingResult.count ?? 0;
  const scansThisMonth = scansThisMonthResult.count ?? 0;
  const reportsThisMonth = reportsThisMonthResult.count ?? 0;

  // Calculate average risk score from latest report per org
  const latestReportsByOrg = new Map<string, number>();
  for (const report of latestReportsResult.data ?? []) {
    if (report.risk_score !== null && !latestReportsByOrg.has(report.org_id)) {
      latestReportsByOrg.set(report.org_id, report.risk_score);
    }
  }
  const riskScores = Array.from(latestReportsByOrg.values());
  const avgRiskScore = riskScores.length > 0
    ? Math.round(riskScores.reduce((a, b) => a + b, 0) / riskScores.length)
    : 0;

  // Registration chart data — last 6 months
  const registrationData: { label: string; value: number }[] = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthEnd = new Date(d.getFullYear(), d.getMonth() + 1, 1);
    const label = d.toLocaleDateString('lt-LT', { year: 'numeric', month: 'short' });
    registrationData.push({ label, value: 0 });

    const { count } = await serviceClient
      .from('organizations')
      .select('id', { count: 'exact', head: true })
      .gte('created_at', d.toISOString())
      .lt('created_at', monthEnd.toISOString());

    registrationData[registrationData.length - 1].value = count ?? 0;
  }

  // Scan activity chart — last 6 months
  const scanActivityData: { label: string; value: number }[] = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthEnd = new Date(d.getFullYear(), d.getMonth() + 1, 1);
    const label = d.toLocaleDateString('lt-LT', { year: 'numeric', month: 'short' });
    scanActivityData.push({ label, value: 0 });

    const { count } = await serviceClient
      .from('scans')
      .select('id', { count: 'exact', head: true })
      .gte('created_at', d.toISOString())
      .lt('created_at', monthEnd.toISOString());

    scanActivityData[scanActivityData.length - 1].value = count ?? 0;
  }

  // Risk distribution — group latest reports by risk level
  let lowRisk = 0;
  let mediumRisk = 0;
  let highRisk = 0;
  for (const score of riskScores) {
    if (score <= 40) lowRisk++;
    else if (score < 70) mediumRisk++;
    else highRisk++;
  }

  // Audit log enrichment — gather user emails and org names
  const auditEntries = auditLogResult.data ?? [];
  const userIds = Array.from(new Set(auditEntries.map((e) => e.user_id).filter(Boolean)));
  const orgIds = Array.from(new Set(auditEntries.map((e) => e.org_id).filter(Boolean)));

  const [, orgsLookup] = await Promise.all([
    Promise.resolve({ data: [] }),
    orgIds.length > 0
      ? serviceClient.from('organizations').select('id, name').in('id', orgIds)
      : Promise.resolve({ data: [] }),
  ]);

  // For user emails, we need auth.users — use a different approach via profiles + auth
  const userEmails = new Map<string, string>();
  if (userIds.length > 0) {
    const { data: authUsers } = await serviceClient.auth.admin.listUsers();
    if (authUsers?.users) {
      for (const u of authUsers.users) {
        userEmails.set(u.id, u.email ?? 'Nežinomas');
      }
    }
  }

  const orgNames = new Map<string, string>();
  for (const org of orgsLookup.data ?? []) {
    orgNames.set(org.id, org.name);
  }

  // SVG icons for KPI cards
  const orgIcon = (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
    </svg>
  );

  const usersIcon = (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  );

  const pendingIcon = (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );

  const scanIcon = (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  );

  const reportIcon = (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  );

  const riskIcon = (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
    </svg>
  );

  return (
    <div className="space-y-8">
      <AdminNav />
      <h1 className="text-2xl font-bold text-gray-900">Administravimo skydelis</h1>

      {/* KPI Cards — 2x3 grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard icon={orgIcon} label="Viso organizacijų" value={totalOrgs} />
        <KpiCard icon={usersIcon} label="Viso vartotojų" value={totalUsers} />
        <KpiCard icon={pendingIcon} label="Laukia patvirtinimo" value={pendingUsers} />
        <KpiCard icon={scanIcon} label="Skenavimai šį mėnesį" value={scansThisMonth} />
        <KpiCard icon={reportIcon} label="Ataskaitos šį mėnesį" value={reportsThisMonth} />
        <KpiCard icon={riskIcon} label="Vidutinis rizikos balas" value={avgRiskScore} />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <BarChart
          title="Registracijos per mėnesį"
          data={registrationData}
          color="bg-blue-500"
        />
        <BarChart
          title="Skenavimų aktyvumas"
          data={scanActivityData}
          color="bg-emerald-500"
        />
        <RiskDistributionChart
          data={[
            { label: 'Žema rizika (0–40)', value: lowRisk, color: 'bg-green-500' },
            { label: 'Vidutinė rizika (41–69)', value: mediumRisk, color: 'bg-yellow-500' },
            { label: 'Aukšta rizika (70–100)', value: highRisk, color: 'bg-red-500' },
          ]}
        />
      </div>

      {/* Audit log feed */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Paskutiniai įvykiai</h3>
        </div>
        <div className="divide-y divide-gray-100">
          {auditEntries.length === 0 ? (
            <div className="px-6 py-8 text-center text-sm text-gray-400">
              Įvykių nėra
            </div>
          ) : (
            auditEntries.map((entry) => (
              <div key={entry.id} className="px-6 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 sm:gap-4">
                <div className="flex items-center space-x-3 min-w-0">
                  <span className="text-xs text-gray-400 whitespace-nowrap">
                    {new Date(entry.created_at).toLocaleString('lt-LT', {
                      year: 'numeric',
                      month: '2-digit',
                      day: '2-digit',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </span>
                  <span className="text-sm font-medium text-gray-900 truncate">
                    {ACTION_LABELS[entry.action] ?? entry.action}
                  </span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-500 min-w-0">
                  <span className="truncate">
                    {entry.user_id ? (userEmails.get(entry.user_id) ?? '—') : '—'}
                  </span>
                  <span className="text-gray-300">|</span>
                  <span className="truncate">
                    {entry.org_id ? (orgNames.get(entry.org_id) ?? '—') : '—'}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
