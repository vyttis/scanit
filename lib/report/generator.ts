import { createServiceRoleClient } from '@/lib/supabase/server';
import { generateExecutiveSummary, generateFindingDescription } from '@/lib/claude/generate-finding-text';
import type { Finding, Report } from '@/types/database';

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 1,
  info: 0,
};

function calculateRiskScore(findings: Finding[]): number {
  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0),
    0,
  );
  return Math.min(100, raw);
}

// ---------------------------------------------------------------------------
// Severity label mapping
// ---------------------------------------------------------------------------

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Kritinis',
  high: 'Aukštas',
  medium: 'Vidutinis',
  low: 'Žemas',
  info: 'Informacinis',
};

// ---------------------------------------------------------------------------
// HTML report builder (converted to PDF via external tool or stored as HTML)
// ---------------------------------------------------------------------------

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#dc2626';
    case 'high': return '#ea580c';
    case 'medium': return '#ca8a04';
    case 'low': return '#2563eb';
    default: return '#6b7280';
  }
}

function riskColor(score: number): string {
  if (score >= 70) return '#dc2626';
  if (score >= 40) return '#ca8a04';
  return '#16a34a';
}

interface ReportData {
  orgName: string;
  domain: string;
  scanDate: string;
  riskScore: number;
  executiveSummary: string;
  findings: Finding[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  reportId: string;
}

function buildReportHtml(data: ReportData): string {
  const findingsHtml = data.findings
    .sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    })
    .map(
      (f) => `
    <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:16px;page-break-inside:avoid;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h3 style="margin:0;font-size:16px;">${escapeHtml(f.title_lt)}</h3>
        <span style="background:${severityColor(f.severity)};color:white;padding:2px 10px;border-radius:4px;font-size:13px;font-weight:600;">
          ${SEVERITY_LABEL[f.severity] ?? f.severity}
        </span>
      </div>
      <p style="margin:4px 0;"><strong>Modulis:</strong> ${escapeHtml(f.module)}</p>
      <p style="margin:4px 0;"><strong>Aprašymas:</strong> ${escapeHtml(f.description_lt)}</p>
      <p style="margin:4px 0;"><strong>Rekomenduojami veiksmai:</strong> ${escapeHtml(f.recommendation_lt)}</p>
      ${f.nis2_article ? `<p style="margin:4px 0;"><strong>KSĮ straipsnis:</strong> ${escapeHtml(f.nis2_article)}</p>` : ''}
      ${f.evidence ? `<details style="margin-top:8px;"><summary style="cursor:pointer;font-size:13px;color:#6b7280;">Techniniai įrodymai</summary><pre style="background:#f9fafb;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto;">${escapeHtml(JSON.stringify(f.evidence, null, 2))}</pre></details>` : ''}
    </div>`,
    )
    .join('\n');

  return `<!DOCTYPE html>
<html lang="lt">
<head><meta charset="UTF-8"><title>Kibernetinio saugumo ataskaita — ${escapeHtml(data.orgName)}</title>
<style>
  @page { margin: 24mm 16mm; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #1f2937; line-height: 1.6; max-width: 800px; margin: 0 auto; }
  .page-break { page-break-before: always; }
  .footer { font-size: 11px; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 8px; margin-top: 32px; }
</style>
</head>
<body>

<!-- Page 1 — Executive Summary -->
<div style="text-align:center;margin-bottom:32px;">
  <h1 style="font-size:24px;margin-bottom:4px;">Kibernetinio saugumo ataskaita</h1>
  <p style="font-size:16px;color:#6b7280;">${escapeHtml(data.orgName)} · ${escapeHtml(data.domain)}</p>
  <p style="font-size:14px;color:#6b7280;">Skenavimo data: ${escapeHtml(data.scanDate)}</p>
</div>

<div style="text-align:center;margin:24px 0;">
  <div style="display:inline-block;width:120px;height:120px;border-radius:50%;border:8px solid ${riskColor(data.riskScore)};line-height:104px;font-size:36px;font-weight:700;color:${riskColor(data.riskScore)};">
    ${data.riskScore}
  </div>
  <p style="font-size:18px;font-weight:600;">Rizikos balas</p>
</div>

<table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
  <tr>
    <td style="text-align:center;padding:8px;"><span style="color:#dc2626;font-size:28px;font-weight:700;">${data.criticalCount}</span><br><small>Kritiniai</small></td>
    <td style="text-align:center;padding:8px;"><span style="color:#ea580c;font-size:28px;font-weight:700;">${data.highCount}</span><br><small>Aukšti</small></td>
    <td style="text-align:center;padding:8px;"><span style="color:#ca8a04;font-size:28px;font-weight:700;">${data.mediumCount}</span><br><small>Vidutiniai</small></td>
    <td style="text-align:center;padding:8px;"><span style="color:#2563eb;font-size:28px;font-weight:700;">${data.lowCount}</span><br><small>Žemi</small></td>
  </tr>
</table>

<h2 style="font-size:18px;">Vykdomoji santrauka</h2>
<p>${escapeHtml(data.executiveSummary)}</p>

<p style="margin-top:16px;font-size:13px;color:#6b7280;font-style:italic;">
  Pagal Kibernetinio saugumo reikalavimų aprašo 45.8 punktą, organizacijos privalo atlikti pažeidžiamumų skenavimą ne rečiau kaip kartą per 6 mėnesius. Ši ataskaita įrodo, kad reikalavimas įvykdytas ${escapeHtml(data.scanDate)}.
</p>

<div class="footer">
  <em>Ši ataskaita parengta vadovaujantis Kibernetinio saugumo įstatymo (2024 m. spalio 3 d. Nr. XIV-2960) ir Kibernetinio saugumo reikalavimų aprašo reikalavimais. Nustatyti trūkumai vertinami pagal NKSC paskelbtas gaires ir ES NIS2 direktyvos (2022/2555) nuostatas.</em>
</div>

<!-- Page 2+ — Findings Detail -->
<div class="page-break"></div>
<h2 style="font-size:20px;margin-bottom:16px;">Nustatyti trūkumai</h2>
${findingsHtml}

<!-- Appendix -->
<div class="page-break"></div>
<h2 style="font-size:20px;margin-bottom:16px;">Priedas — NKSC patikrinimo įrodymas</h2>
<pre style="background:#f9fafb;padding:16px;border-radius:8px;font-size:13px;line-height:1.8;">
NKSC PATIKRINIMO ĮRODYMAS
───────────────────────────────────────────────
Organizacija:        ${escapeHtml(data.orgName)}
Domenas:             ${escapeHtml(data.domain)}
Skenavimo data:      ${escapeHtml(data.scanDate)} UTC+2
Skenavimo metodas:   Automatinis išorinis pažeidžiamumų skenavimas
Apimtis:             Viešai prieinami ištekliai (domenas ir IP adresai)
Teisinis pagrindas:  KSRA 45.8 str.
Platformos operatorius: scanit.lt
Ataskaitos ID:       ${escapeHtml(data.reportId)}
───────────────────────────────────────────────
Šis dokumentas gali būti pateiktas NKSC kaip pažeidžiamumų
skenavimo įvykdymo įrodymas pagal KSĮ reikalavimus.
</pre>

<h3 style="font-size:16px;margin-top:24px;">Skenavimo apimtis</h3>
<ul>
  <li><strong>Domenas:</strong> ${escapeHtml(data.domain)}</li>
  <li><strong>Moduliai:</strong> Shodan, HIBP, SSL Labs, MXToolbox, SecurityTrails, VirusTotal, AbuseIPDB, URLScan</li>
  <li><strong>Skenavimo data:</strong> ${escapeHtml(data.scanDate)}</li>
</ul>

<div class="footer">
  <em>Ši ataskaita parengta vadovaujantis Kibernetinio saugumo įstatymo (2024 m. spalio 3 d. Nr. XIV-2960) ir Kibernetinio saugumo reikalavimų aprašo reikalavimais. Nustatyti trūkumai vertinami pagal NKSC paskelbtas gaires ir ES NIS2 direktyvos (2022/2555) nuostatas.</em>
</div>

</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main report generation pipeline
// ---------------------------------------------------------------------------

export interface GenerateReportResult {
  reportId: string;
  pdfPath: string;
  signedUrl: string;
  riskScore: number;
}

/**
 * Full report generation pipeline:
 * 1. Fetch findings for scan
 * 2. Enrich findings with Claude-generated Lithuanian text (if needed)
 * 3. Calculate risk score
 * 4. Generate executive summary via Claude
 * 5. Build HTML report
 * 6. Store in Supabase Storage
 * 7. Create report record in DB
 * 8. Return signed URL
 */
export async function generateReport(scanId: string): Promise<GenerateReportResult> {
  const serviceClient = createServiceRoleClient();

  // 1. Fetch scan + organization
  const { data: scan, error: scanError } = await serviceClient
    .from('scans')
    .select('*')
    .eq('id', scanId)
    .single();

  if (scanError || !scan) {
    throw new Error(`Skenavimas nerastas: ${scanId}`);
  }

  if (scan.status !== 'completed') {
    throw new Error(`Skenavimas dar nebaigtas (būsena: ${scan.status})`);
  }

  const { data: org, error: orgError } = await serviceClient
    .from('organizations')
    .select('*')
    .eq('id', scan.org_id)
    .single();

  if (orgError || !org) {
    throw new Error(`Organizacija nerasta: ${scan.org_id}`);
  }

  // 2. Fetch findings
  const { data: findings, error: findingsError } = await serviceClient
    .from('findings')
    .select('*')
    .eq('scan_id', scanId);

  if (findingsError) {
    throw new Error(`Klaida gaunant skenavimo rezultatus: ${findingsError.message}`);
  }

  const allFindings: Finding[] = findings ?? [];

  // 3. Enrich findings with Claude-generated descriptions where missing/placeholder
  const enrichedFindings = await enrichFindings(allFindings);

  // 4. Calculate risk score
  const riskScore = calculateRiskScore(enrichedFindings);

  const criticalCount = enrichedFindings.filter((f) => f.severity === 'critical').length;
  const highCount = enrichedFindings.filter((f) => f.severity === 'high').length;
  const mediumCount = enrichedFindings.filter((f) => f.severity === 'medium').length;
  const lowCount = enrichedFindings.filter((f) => f.severity === 'low').length;

  // 5. Generate executive summary
  const executiveSummary = await generateExecutiveSummary(
    org.name,
    enrichedFindings,
    riskScore,
  );

  // 6. Build HTML report
  const scanDate = scan.completed_at
    ? new Date(scan.completed_at).toISOString().split('T')[0]
    : new Date().toISOString().split('T')[0];

  const reportId = crypto.randomUUID();
  const html = buildReportHtml({
    orgName: org.name,
    domain: org.domain,
    scanDate,
    riskScore,
    executiveSummary,
    findings: enrichedFindings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    reportId,
  });

  // 7. Store HTML report in Supabase Storage (private bucket)
  const pdfPath = `reports/${org.id}/${scanId}/${reportId}.html`;

  const { error: uploadError } = await serviceClient.storage
    .from('reports')
    .upload(pdfPath, Buffer.from(html, 'utf-8'), {
      contentType: 'text/html',
      upsert: false,
    });

  if (uploadError) {
    throw new Error(`Klaida įkeliant ataskaitą: ${uploadError.message}`);
  }

  // 8. Create report record
  const { error: reportInsertError } = await serviceClient
    .from('reports')
    .insert({
      id: reportId,
      scan_id: scanId,
      org_id: org.id,
      pdf_path: pdfPath,
      risk_score: riskScore,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount,
    });

  if (reportInsertError) {
    throw new Error(`Klaida kuriant ataskaitos įrašą: ${reportInsertError.message}`);
  }

  // 9. Generate signed URL (1-hour expiry)
  const { data: signedUrlData, error: signedUrlError } = await serviceClient.storage
    .from('reports')
    .createSignedUrl(pdfPath, 3600);

  if (signedUrlError || !signedUrlData?.signedUrl) {
    throw new Error(`Klaida generuojant pasirašytą URL: ${signedUrlError?.message}`);
  }

  return {
    reportId,
    pdfPath,
    signedUrl: signedUrlData.signedUrl,
    riskScore,
  };
}

/**
 * Enrich findings with Claude-generated Lithuanian descriptions.
 * Only calls Claude for findings that appear to have placeholder text.
 */
async function enrichFindings(findings: Finding[]): Promise<Finding[]> {
  const enriched: Finding[] = [];

  for (const finding of findings) {
    const needsEnrichment =
      !finding.description_lt ||
      finding.description_lt.length < 20 ||
      finding.description_lt === finding.title_lt;

    if (needsEnrichment) {
      try {
        const generated = await generateFindingDescription({
          module: finding.module,
          severity: finding.severity,
          title_lt: finding.title_lt,
          evidence: finding.evidence,
        });
        enriched.push({
          ...finding,
          description_lt: generated.description_lt,
          recommendation_lt: generated.recommendation_lt,
        });
      } catch (err) {
        console.error(`Failed to enrich finding ${finding.id}:`, err);
        enriched.push(finding);
      }
    } else {
      enriched.push(finding);
    }
  }

  return enriched;
}
