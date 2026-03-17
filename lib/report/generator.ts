import { createServiceRoleClient } from '@/lib/supabase/server';
import { generateExecutiveSummary, generateFindingDescription } from '@/lib/claude/generate-finding-text';
import type { Finding } from '@/types/database';
import { formatReportDate } from '@/lib/utils/date';
import { computeScanDelta, type ScanDelta } from '@/lib/utils/scan-delta';
import { evaluateCompliance, calculateCompliancePercentage, type ArticleComplianceResult } from '@/lib/utils/compliance-mapping';

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
  if (score >= 41) return '#ca8a04';
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
  scanDelta?: ScanDelta | null;
  complianceResults?: ArticleComplianceResult[];
  compliancePercent?: number;
  trendScores?: { date: string; score: number }[];
}

function buildReportHtml(data: ReportData): string {
  const findingsHtml = data.findings
    .sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    })
    .map(
      (f) => {
        const borderColor = severityColor(f.severity);
        const descParagraphs = escapeHtml(f.description_lt)
          .split(/\n\n/)
          .map(p => `<p style="margin:6px 0;font-size:14px;line-height:1.6;">${p}</p>`)
          .join('');
        const recParagraphs = escapeHtml(f.recommendation_lt)
          .split(/\n/)
          .map(p => `<p style="margin:4px 0;font-size:14px;line-height:1.6;">${p}</p>`)
          .join('');

        return `
    <div style="border:1px solid #e5e7eb;border-left:4px solid ${borderColor};border-radius:8px;padding:0;margin-bottom:20px;page-break-inside:avoid;">
      <div style="padding:10px 16px;background:#f9fafb;border-bottom:1px solid #e5e7eb;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <span style="background:${severityColor(f.severity)};color:white;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600;">
          ${SEVERITY_LABEL[f.severity] ?? f.severity}
        </span>
        <span style="font-size:12px;color:#6b7280;background:white;padding:2px 8px;border-radius:4px;border:1px solid #e5e7eb;">${escapeHtml(f.module)}</span>
        ${f.nis2_article ? `<span style="font-size:12px;color:#7c3aed;background:#f5f3ff;padding:2px 8px;border-radius:4px;border:1px solid #ddd6fe;">KSĮ ${escapeHtml(f.nis2_article)}</span>` : ''}
      </div>
      <div style="padding:16px;">
        <h3 style="margin:0 0 12px 0;font-size:16px;font-weight:600;">${escapeHtml(f.title_lt)}</h3>
        <div style="margin-bottom:12px;">${descParagraphs}</div>
        <div style="border-top:1px solid #e5e7eb;padding-top:12px;">
          <p style="margin:0 0 4px 0;font-size:13px;font-weight:700;color:#374151;text-transform:uppercase;letter-spacing:0.05em;">Rekomenduojami veiksmai</p>
          ${recParagraphs}
        </div>
        ${f.evidence ? `<details style="margin-top:12px;"><summary style="cursor:pointer;font-size:13px;color:#6b7280;">Techninė informacija</summary><pre style="background:#f9fafb;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;margin-top:8px;">${escapeHtml(JSON.stringify(f.evidence, null, 2))}</pre></details>` : ''}
      </div>
    </div>`;
      },
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

${data.scanDelta ? `
<h2 style="font-size:18px;margin-top:24px;">Palyginimas su praėjusiu skaitymu</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
  <tr>
    <td style="text-align:center;padding:12px;background:#fef2f2;border-radius:8px;"><span style="color:#dc2626;font-size:24px;font-weight:700;">${data.scanDelta.newCount}</span><br><small style="color:#991b1b;">Nauji trūkumai</small></td>
    <td style="width:8px;"></td>
    <td style="text-align:center;padding:12px;background:#f0fdf4;border-radius:8px;"><span style="color:#16a34a;font-size:24px;font-weight:700;">${data.scanDelta.resolvedCount}</span><br><small style="color:#166534;">Išspręsti</small></td>
    <td style="width:8px;"></td>
    <td style="text-align:center;padding:12px;background:#f9fafb;border-radius:8px;"><span style="color:#6b7280;font-size:24px;font-weight:700;">${data.scanDelta.persistentCount}</span><br><small style="color:#374151;">Išlikę</small></td>
  </tr>
</table>
` : ''}

${data.complianceResults ? `
<h2 style="font-size:18px;margin-top:24px;">KSĮ atitikties santrauka — ${data.compliancePercent ?? 0}%</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px;font-size:13px;">
  <tr style="background:#f9fafb;">
    <th style="text-align:left;padding:8px;border-bottom:1px solid #e5e7eb;">Straipsnis</th>
    <th style="text-align:left;padding:8px;border-bottom:1px solid #e5e7eb;">Reikalavimas</th>
    <th style="text-align:center;padding:8px;border-bottom:1px solid #e5e7eb;">Būsena</th>
    <th style="text-align:center;padding:8px;border-bottom:1px solid #e5e7eb;">Trūkumų</th>
  </tr>
  ${data.complianceResults.map(r => {
    const statusColor = r.status === 'pass' ? '#16a34a' : r.status === 'partial' ? '#ca8a04' : r.status === 'fail' ? '#dc2626' : '#6b7280';
    const statusLabel = r.status === 'pass' ? 'Atitinka' : r.status === 'partial' ? 'Dalinis' : r.status === 'fail' ? 'Neatitinka' : 'Netikrinta';
    return `<tr>
      <td style="padding:8px;border-bottom:1px solid #f3f4f6;">${escapeHtml(r.article.id)}</td>
      <td style="padding:8px;border-bottom:1px solid #f3f4f6;">${escapeHtml(r.article.title)}</td>
      <td style="text-align:center;padding:8px;border-bottom:1px solid #f3f4f6;"><span style="color:${statusColor};font-weight:600;">${statusLabel}</span></td>
      <td style="text-align:center;padding:8px;border-bottom:1px solid #f3f4f6;">${r.findingCount || '—'}</td>
    </tr>`;
  }).join('')}
</table>
` : ''}

${data.trendScores && data.trendScores.length >= 2 ? `
<h2 style="font-size:18px;margin-top:24px;">Rizikos balo tendencija</h2>
<div style="display:flex;align-items:flex-end;gap:8px;height:100px;margin-bottom:16px;">
  ${data.trendScores.map(t => {
    const height = Math.max(4, t.score);
    const color = t.score >= 70 ? '#dc2626' : t.score >= 41 ? '#ca8a04' : '#16a34a';
    return `<div style="flex:1;text-align:center;">
      <div style="font-size:11px;font-weight:600;color:${color};margin-bottom:4px;">${t.score}</div>
      <div style="background:${color};height:${height}px;border-radius:4px 4px 0 0;"></div>
      <div style="font-size:10px;color:#6b7280;margin-top:4px;">${escapeHtml(t.date)}</div>
    </div>`;
  }).join('')}
</div>
` : ''}

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
// Storage bucket helper
// ---------------------------------------------------------------------------

async function ensureReportsBucket(client: ReturnType<typeof createServiceRoleClient>) {
  const { data: buckets } = await client.storage.listBuckets();
  const exists = buckets?.some(b => b.name === 'reports');
  if (!exists) {
    const { error } = await client.storage.createBucket('reports', {
      public: false,
      fileSizeLimit: 10485760, // 10MB max
    });
    if (error) {
      console.error('Failed to create reports bucket:', error);
      throw new Error(`Failed to create storage bucket: ${error.message}`);
    }
  }
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

  // Ensure storage bucket exists before attempting upload
  await ensureReportsBucket(serviceClient);

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

  // 6. Compute scan delta (vs previous scan)
  let scanDelta: ScanDelta | null = null;
  const { data: prevScansArr } = await serviceClient
    .from('scans')
    .select('id')
    .eq('org_id', org.id)
    .eq('status', 'completed')
    .neq('id', scanId)
    .order('created_at', { ascending: false })
    .limit(1);

  if (prevScansArr?.[0]) {
    const { data: prevFindings } = await serviceClient
      .from('findings')
      .select('*')
      .eq('scan_id', prevScansArr[0].id);

    if (prevFindings && prevFindings.length > 0) {
      scanDelta = computeScanDelta(enrichedFindings, prevFindings as Finding[]);
    }
  }

  // 7. Compute compliance
  const complianceResults = evaluateCompliance(enrichedFindings);
  const compliancePercent = calculateCompliancePercentage(complianceResults);

  // 8. Get trend data (last 6 reports)
  const { data: trendReports } = await serviceClient
    .from('reports')
    .select('risk_score, created_at')
    .eq('org_id', org.id)
    .order('created_at', { ascending: true })
    .limit(6);

  const trendScores = (trendReports ?? [])
    .filter((r) => r.risk_score !== null)
    .map((r) => ({
      date: formatReportDate(r.created_at),
      score: r.risk_score as number,
    }));

  // 9. Build HTML report
  const scanDate = formatReportDate(scan.completed_at || new Date());

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
    scanDelta,
    complianceResults,
    compliancePercent,
    trendScores,
  });

  // 7. Try PDF generation via Puppeteer + chromium-min, fall back to HTML
  let pdfPath: string;
  let uploadBuffer: Buffer;
  let uploadContentType: string;

  try {
    const { htmlToPdf } = await import('@/lib/report/html-to-pdf');
    const pdfBuffer = await htmlToPdf(html);
    pdfPath = `reports/${org.id}/${scanId}/${reportId}.pdf`;
    uploadBuffer = pdfBuffer;
    uploadContentType = 'application/pdf';
    console.log(`Report ${reportId}: PDF generated successfully`);
  } catch (pdfErr) {
    // Puppeteer/Chromium not available — fall back to HTML
    console.warn(`Report ${reportId}: PDF generation failed, falling back to HTML:`, pdfErr);
    pdfPath = `reports/${org.id}/${scanId}/${reportId}.html`;
    uploadBuffer = Buffer.from(html, 'utf-8');
    uploadContentType = 'text/html';
  }

  const { error: uploadError } = await serviceClient.storage
    .from('reports')
    .upload(pdfPath, uploadBuffer, {
      contentType: uploadContentType,
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
 * Always enriches non-info findings to add structured sections
 * (KAS TAI, KODĖL TAI PAVOJINGA, VERSLO POVEIKIS).
 * Info findings keep their scanner-generated text as-is.
 */
async function enrichFindings(findings: Finding[]): Promise<Finding[]> {
  const enriched: Finding[] = [];
  const hasApiKey = !!process.env.ANTHROPIC_API_KEY;

  if (!hasApiKey) {
    console.warn('ANTHROPIC_API_KEY not set — skipping Claude enrichment');
    return findings;
  }

  for (const finding of findings) {
    // Always enrich non-info findings for structured sections
    // Skip info findings — their scanner-generated text is sufficient
    const shouldEnrich = finding.severity !== 'info';

    if (shouldEnrich) {
      try {
        console.log(`Enriching finding: ${finding.module} / ${finding.severity} / ${finding.title_lt.slice(0, 60)}`);
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
