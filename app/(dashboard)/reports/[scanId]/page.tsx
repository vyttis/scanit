import { createServerSupabaseClient, createServiceRoleClient } from '@/lib/supabase/server';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { ReportViewer } from '@/components/report-viewer';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function ReportViewerPage({ params }: { params: { scanId: string } }) {
  const { scanId } = params;

  if (!UUID_REGEX.test(scanId)) {
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
  const queryClient = isSuperadmin ? serviceClient : supabase;

  // Fetch report (use limit(1) + maybeSingle to handle duplicate reports per scan)
  const { data: report } = await queryClient
    .from('reports')
    .select('id, scan_id, org_id, pdf_path')
    .eq('scan_id', scanId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!report || !report.pdf_path) {
    notFound();
  }

  // Verify org ownership for non-superadmin
  if (!isSuperadmin && profile?.org_id && report.org_id !== profile.org_id) {
    notFound();
  }

  // Fetch org name for display
  const { data: org } = await serviceClient
    .from('organizations')
    .select('name, domain')
    .eq('id', report.org_id)
    .single();

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between bg-white rounded-lg shadow-md p-4">
        <div className="flex items-center gap-4">
          <Link href={`/scans/${scanId}`} className="text-sm text-blue-600 hover:text-blue-800">
            &larr; Skenavimo rezultatai
          </Link>
          <span className="text-gray-300">|</span>
          <div>
            <h1 className="text-lg font-bold text-gray-900">Ataskaita</h1>
            {org && (
              <p className="text-xs text-gray-500">{org.name} &middot; {org.domain}</p>
            )}
          </div>
        </div>
      </div>

      {/* Report content rendered in iframe from our proxy, with download/print toolbar */}
      <ReportViewer scanId={scanId} />
    </div>
  );
}
