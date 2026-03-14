import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { resolve } from 'dns/promises';

/**
 * AbuseIPDB scanner — full IP abuse intelligence.
 * 1. Resolve ALL IPs for domain (A records)
 * 2. For each IP: GET /api/v2/check — confidence score, reports, ISP, usage type
 *
 * Severity: Critical if score ≥75, High if ≥50 or 10+ reports, Medium if ≥25, Low if any
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
export async function scanAbuseipdb(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.ABUSEIPDB_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'abuseipdb', success: false, findings: [], error: 'ABUSEIPDB_API_KEY not configured' };
  }

  const headers = { Key: apiKey, Accept: 'application/json' };

  try {
    let ips: string[] = [];
    try {
      ips = await resolve(domain, 'A');
    } catch {
      return {
        module: 'abuseipdb', success: true,
        findings: [{
          module: 'abuseipdb', severity: 'info',
          title_lt: 'DNS rezoliucija nepavyko',
          description_lt: `Nepavyko nustatyti domeno ${domain} IP adresų.`,
          recommendation_lt: 'Patikrinkite DNS konfigūraciją.',
          nis2_article: null, evidence: { domain },
        }],
      };
    }

    if (ips.length === 0) {
      return {
        module: 'abuseipdb', success: true,
        findings: [{
          module: 'abuseipdb', severity: 'info',
          title_lt: 'IP adresas nerastas',
          description_lt: `Domenas ${domain} neturi A įrašo.`,
          recommendation_lt: 'Patikrinkite DNS konfigūraciją.',
          nis2_article: null, evidence: { domain },
        }],
      };
    }

    const findings: ScannerFinding[] = [];

    interface IpCheckResult {
      ip: string; confidenceScore: number; totalReports: number;
      lastReportedAt: string | null; countryCode: string;
      usageType: string; isp: string; numDistinctUsers: number;
      abuseCategories: number[];
    }

    const categoryNames: Record<number, string> = {
      1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
      5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
      9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
      14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
      17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
      21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
    };

    const ipResults: IpCheckResult[] = [];

    for (const ip of ips.slice(0, 5)) {
      try {
        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
        console.log(`[abuseipdb] Checking IP: ${ip}`);
        const res = await fetchWithTimeout(url, { headers }, 15_000);
        console.log(`[abuseipdb] Response for ${ip}: ${res.status}`);

        if (!res.ok) { await res.text().catch(() => ''); continue; }

        const responseData = await res.json();
        const d = responseData.data;

        ipResults.push({
          ip,
          confidenceScore: d.abuseConfidenceScore || 0,
          totalReports: d.totalReports || 0,
          lastReportedAt: d.lastReportedAt || null,
          countryCode: d.countryCode || '',
          usageType: d.usageType || '',
          isp: d.isp || '',
          numDistinctUsers: d.numDistinctUsers || 0,
          abuseCategories: (d.reports || []).flatMap((r: { categories: number[] }) => r.categories || []),
        });
      } catch { continue; }
    }

    if (ipResults.length === 0) {
      return { module: 'abuseipdb', success: false, findings: [], error: 'Failed to check any IPs' };
    }

    for (const result of ipResults) {
      const score = result.confidenceScore;
      const reports = result.totalReports;

      const categoryCounts = new Map<number, number>();
      for (const cat of result.abuseCategories) {
        categoryCounts.set(cat, (categoryCounts.get(cat) || 0) + 1);
      }
      const topCategories = Array.from(categoryCounts.entries())
        .sort((a, b) => b[1] - a[1]).slice(0, 5)
        .map(([cat, count]) => `${categoryNames[cat] || `Kat.${cat}`} (${count}×)`);

      if (score >= 75) {
        findings.push({
          module: 'abuseipdb', severity: 'critical',
          title_lt: `IP ${result.ip} — kritinis piktnaudžiavimo lygis (${score}%)`,
          description_lt:
            `IP adresas ${result.ip} (${domain}) turi ${score}% piktnaudžiavimo balą ` +
            `(${reports} pranešimų per 90 dienų, ${result.numDistinctUsers} unikalių pranešėjų).\n\n` +
            `Serveris gali būti pažeistas ir naudojamas atakoms.\n` +
            `${topCategories.length > 0 ? `Kategorijos: ${topCategories.join(', ')}\n` : ''}` +
            `ISP: ${result.isp}, šalis: ${result.countryCode}, tipas: ${result.usageType}\n` +
            `${result.lastReportedAt ? `Paskutinis pranešimas: ${result.lastReportedAt}` : ''}`,
          recommendation_lt:
            `1. SKUBIAI (per 24 val.): patikrinkite serverio saugumą.\n` +
            `2. Ieškokite kenkėjiškos programinės įrangos ir backdoor.\n` +
            `3. Apsvarstykite serverio izoliavimą.\n` +
            `4. Praneškite CERT-LT.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain, ip: result.ip, abuse_confidence: score, total_reports: reports,
            distinct_users: result.numDistinctUsers, isp: result.isp, country: result.countryCode,
            usage_type: result.usageType, last_reported: result.lastReportedAt, top_categories: topCategories,
          },
        });
      } else if (score >= 50 || reports >= 10) {
        findings.push({
          module: 'abuseipdb', severity: 'high',
          title_lt: `IP ${result.ip} — aukštas piktnaudžiavimo lygis (${score}%, ${reports} pranešimų)`,
          description_lt:
            `IP adresas ${result.ip} (${domain}) turi ${score}% piktnaudžiavimo balą (${reports} pranešimų).\n` +
            `${topCategories.length > 0 ? `Kategorijos: ${topCategories.join(', ')}\n` : ''}` +
            `ISP: ${result.isp}, šalis: ${result.countryCode}`,
          recommendation_lt:
            `1. Patikrinkite serverio saugumą.\n` +
            `2. Ieškokite neautorizuotos prieigos požymių.\n` +
            `3. Stebėkite tinklo srautą.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain, ip: result.ip, abuse_confidence: score, total_reports: reports,
            isp: result.isp, country: result.countryCode, last_reported: result.lastReportedAt, top_categories: topCategories,
          },
        });
      } else if (score >= 25) {
        findings.push({
          module: 'abuseipdb', severity: 'medium',
          title_lt: `IP ${result.ip} — vidutinis piktnaudžiavimo lygis (${score}%)`,
          description_lt: `IP ${result.ip} (${domain}) turi ${score}% piktnaudžiavimo balą (${reports} pranešimų). Verta stebėti.`,
          recommendation_lt: 'Stebėkite serverio veiklą.',
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: { domain, ip: result.ip, abuse_confidence: score, total_reports: reports, isp: result.isp, country: result.countryCode },
        });
      } else if (reports > 0) {
        findings.push({
          module: 'abuseipdb', severity: 'low',
          title_lt: `IP ${result.ip} — nedaug pranešimų (${reports} vnt.)`,
          description_lt: `IP ${result.ip} (${domain}) turi ${reports} pranešimų (balas: ${score}%). Gali būti klaidingi teigiami.`,
          recommendation_lt: 'Stebėkite situaciją.',
          nis2_article: null,
          evidence: { domain, ip: result.ip, abuse_confidence: score, total_reports: reports },
        });
      }
    }

    // All clean
    if (ipResults.every((r) => r.totalReports === 0)) {
      findings.push({
        module: 'abuseipdb', severity: 'info',
        title_lt: 'IP adresų reputacija gera — piktnaudžiavimo nenustatyta',
        description_lt:
          `Visi ${ipResults.length} domeno ${domain} IP adresai neturi pranešimų per 90 dienų.\n` +
          ipResults.map((r) => `• ${r.ip} — ISP: ${r.isp}, šalis: ${r.countryCode}, tipas: ${r.usageType}`).join('\n'),
        recommendation_lt: 'Jokių veiksmų nereikia.',
        nis2_article: null,
        evidence: {
          domain,
          checked_ips: ipResults.map((r) => ({ ip: r.ip, abuse_confidence: 0, total_reports: 0, isp: r.isp, country: r.countryCode, usage_type: r.usageType })),
        },
      });
    }

    // Multi-IP summary
    if (ipResults.length > 1 && findings.some((f) => f.severity !== 'info')) {
      findings.push({
        module: 'abuseipdb', severity: 'info',
        title_lt: `AbuseIPDB suvestinė — ${ipResults.length} IP patikrinta`,
        description_lt:
          ipResults.map((r) => `• ${r.ip} — balas: ${r.confidenceScore}%, pranešimai: ${r.totalReports}, ISP: ${r.isp}`).join('\n'),
        recommendation_lt: 'Žr. aukščiau.',
        nis2_article: null,
        evidence: { domain, ip_summary: ipResults.map((r) => ({ ip: r.ip, score: r.confidenceScore, reports: r.totalReports })) },
      });
    }

    return { module: 'abuseipdb', success: true, findings };
  } catch (err) {
    return { module: 'abuseipdb', success: false, findings: [], error: err instanceof Error ? err.message : 'Unknown error' };
  }
}
