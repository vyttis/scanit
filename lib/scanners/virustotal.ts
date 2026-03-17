import type { ScannerResult, ScannerFinding, ScannerOptions } from './types';
import { fetchWithTimeout, expandCidrToIps, deduplicateIps } from './types';
import { resolve } from 'dns/promises';

/**
 * VirusTotal scanner — full domain/IP reputation intelligence.
 * 1. Domain report: GET /api/v3/domains/{domain}
 * 2. IP reputation: GET /api/v3/ip_addresses/{ip}
 * 3. Communicating/downloaded files relationships
 * 4. URL scan: POST /api/v3/urls
 *
 * Severity: Critical if 3+ vendors malicious or communicating malware,
 *           High if 1-2 vendors, Medium if suspicious categories
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function scanVirustotal(domain: string, options?: ScannerOptions): Promise<ScannerResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'virustotal', success: false, findings: [], error: 'VIRUSTOTAL_API_KEY not configured' };
  }

  const vtHeaders = { 'x-apikey': apiKey, Accept: 'application/json' };

  try {
    const findings: ScannerFinding[] = [];

    // ── 1. Domain report ─────────────────────────────────────────────
    console.log(`[virustotal] GET domain/${domain}`);
    const res = await fetchWithTimeout(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      { headers: vtHeaders },
      15_000,
    );
    console.log(`[virustotal] Response: ${res.status}`);

    if (!res.ok) {
      await res.text().catch(() => '');
      return { module: 'virustotal', success: false, findings: [], error: `VirusTotal API returned: ${res.status}` };
    }

    const data = await res.json();
    const attributes = data.data?.attributes || {};
    const lastAnalysis = attributes.last_analysis_stats || {};
    const malicious = lastAnalysis.malicious || 0;
    const suspicious = lastAnalysis.suspicious || 0;
    const harmless = lastAnalysis.harmless || 0;
    const undetected = lastAnalysis.undetected || 0;
    const totalEngines = harmless + malicious + suspicious + undetected;

    const lastResults = attributes.last_analysis_results || {};
    const maliciousVendors = Object.entries(lastResults)
      .filter(([, r]) => (r as { category: string }).category === 'malicious')
      .map(([vendor]) => vendor);
    const suspiciousVendors = Object.entries(lastResults)
      .filter(([, r]) => (r as { category: string }).category === 'suspicious')
      .map(([vendor]) => vendor);

    const categories = attributes.categories || {};
    const categoryList = Object.entries(categories).map(([v, c]) => `${v}: ${c}`).slice(0, 10);
    const reputation = typeof attributes.reputation === 'number' ? attributes.reputation : null;

    // Communicating files
    let communicatingFilesCount = 0;
    try {
      const commRes = await fetchWithTimeout(
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/communicating_files?limit=10`,
        { headers: vtHeaders }, 10_000,
      );
      if (commRes.ok) {
        const commData = await commRes.json();
        communicatingFilesCount = commData.meta?.count || (commData.data || []).length;
      }
    } catch { /* non-critical */ }

    // Downloaded files
    let downloadedFilesCount = 0;
    try {
      const dlRes = await fetchWithTimeout(
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/downloaded_files?limit=10`,
        { headers: vtHeaders }, 10_000,
      );
      if (dlRes.ok) {
        const dlData = await dlRes.json();
        downloadedFilesCount = dlData.meta?.count || (dlData.data || []).length;
      }
    } catch { /* non-critical */ }

    // Subdomains seen by VT
    let vtSubdomains: string[] = [];
    try {
      const subRes = await fetchWithTimeout(
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/subdomains?limit=20`,
        { headers: vtHeaders }, 10_000,
      );
      if (subRes.ok) {
        const subData = await subRes.json();
        vtSubdomains = (subData.data || []).map((d: { id: string }) => d.id);
      }
    } catch { /* non-critical */ }

    // Critical: 3+ malicious or communicating malware
    if (malicious >= 3 || communicatingFilesCount > 0) {
      findings.push({
        module: 'virustotal',
        severity: 'critical',
        title_lt: `Domenas pažymėtas kaip kenkėjiškas — ${malicious} saugumo variklių`,
        description_lt:
          `Domenas ${domain} pažymėtas kaip kenkėjiškas ${malicious} iš ${totalEngines} saugumo variklių` +
          `${maliciousVendors.length > 0 ? ` (${maliciousVendors.slice(0, 10).join(', ')})` : ''}.\n\n` +
          `${communicatingFilesCount > 0 ? `⚠ Aptikta ${communicatingFilesCount} kenkėjiškų programų, kurios komunikuoja su šiuo domenu (C2 valdymo centras).\n` : ''}` +
          `${downloadedFilesCount > 0 ? `⚠ Domenas platina ${downloadedFilesCount} kenkėjiškų failų.\n` : ''}` +
          `Kategorijos: ${categoryList.length > 0 ? categoryList.join('; ') : 'nenustatytos'}\n` +
          `Reputacija: ${reputation ?? 'nenustatyta'}`,
        recommendation_lt:
          `1. SKUBIAI (per 24 val.): ištirkite priežastis.\n` +
          `2. Patikrinkite serverį dėl kenkėjiškos programinės įrangos.\n` +
          `3. Jei pažeistas — izoliuokite ir atkurkite iš atsarginės kopijos.\n` +
          `4. Kreipkitės dėl domeno reputacijos atkūrimo.\n` +
          `5. Praneškite CERT-LT.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain, malicious_count: malicious, suspicious_count: suspicious, total_engines: totalEngines,
          flagged_by: maliciousVendors.slice(0, 15),
          communicating_files: communicatingFilesCount, downloaded_files: downloadedFilesCount,
          categories, reputation,
        },
      });
    } else if (malicious > 0 || suspicious > 0 || downloadedFilesCount > 0) {
      findings.push({
        module: 'virustotal',
        severity: 'high',
        title_lt: `Domeno reputacijos įspėjimai — ${malicious} kenkėjiški, ${suspicious} įtartini`,
        description_lt:
          `Domenas ${domain} turi ${malicious} kenkėjiškų ir ${suspicious} įtartinų pažymėjimų iš ${totalEngines} variklių.\n` +
          `${maliciousVendors.length > 0 ? `Kenkėjišku: ${maliciousVendors.join(', ')}\n` : ''}` +
          `${suspiciousVendors.length > 0 ? `Įtartinu: ${suspiciousVendors.join(', ')}\n` : ''}` +
          `${downloadedFilesCount > 0 ? `Platina ${downloadedFilesCount} kenkėjiškų failų.\n` : ''}`,
        recommendation_lt:
          `1. Patikrinkite domeno turinį ir serverio konfigūraciją.\n` +
          `2. Stebėkite situaciją.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain, malicious_count: malicious, suspicious_count: suspicious, total_engines: totalEngines,
          flagged_by_malicious: maliciousVendors, flagged_by_suspicious: suspiciousVendors,
          downloaded_files: downloadedFilesCount,
        },
      });
    }

    if (reputation !== null && reputation < -5) {
      findings.push({
        module: 'virustotal',
        severity: 'medium',
        title_lt: `Neigiama domeno reputacija: ${reputation}`,
        description_lt: `Domeno ${domain} reputacijos balas yra ${reputation}. Neigiamas balas rodo, kad bendruomenė pažymėjo domeną kaip problematišką.`,
        recommendation_lt: 'Peržiūrėkite domeno turinį ir ištirkite priežastis.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, reputation },
      });
    }

    // ── 2. IP reputation ─────────────────────────────────────────────
    let domainIps: string[] = [];
    try { domainIps = await resolve(domain, 'A'); } catch { /* ignore */ }

    // Merge user-provided IP ranges (professional plan)
    const extraIps = options?.ipRanges ? expandCidrToIps(options.ipRanges, 10) : [];
    const allIpsForVt = deduplicateIps([...domainIps.slice(0, 3), ...extraIps]);
    const maxVtIps = extraIps.length > 0 ? 10 : 3;

    let vtIpCount = 0;
    for (const ip of allIpsForVt.slice(0, maxVtIps)) {
      // VT rate limit: 4 req/min. Add delay when checking many IPs.
      if (vtIpCount >= 4) {
        console.log(`[virustotal] Rate limit pause (15s) after ${vtIpCount} IP lookups`);
        await sleep(15_000);
        vtIpCount = 0;
      }
      vtIpCount++;
      try {
        const ipRes = await fetchWithTimeout(
          `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
          { headers: vtHeaders }, 10_000,
        );
        if (!ipRes.ok) continue;

        const ipData = await ipRes.json();
        const ipAttrs = ipData.data?.attributes || {};
        const ipStats = ipAttrs.last_analysis_stats || {};
        const ipMal = ipStats.malicious || 0;
        const ipSusp = ipStats.suspicious || 0;
        const ipTotal = (ipStats.harmless || 0) + ipMal + ipSusp + (ipStats.undetected || 0);

        if (ipMal >= 3) {
          const ipMalVendors = Object.entries(ipAttrs.last_analysis_results || {})
            .filter(([, r]) => (r as { category: string }).category === 'malicious')
            .map(([v]) => v).slice(0, 10);

          findings.push({
            module: 'virustotal',
            severity: 'high',
            title_lt: `IP adresas ${ip} pažymėtas kaip kenkėjiškas — ${ipMal} variklių`,
            description_lt:
              `IP ${ip} (${domain}) pažymėtas kaip kenkėjiškas ${ipMal} iš ${ipTotal} variklių: ${ipMalVendors.join(', ')}.`,
            recommendation_lt: 'Patikrinkite serverio saugumą. Apsvarstykite IP pakeitimą.',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { ip, domain, malicious: ipMal, suspicious: ipSusp, total: ipTotal, flagged_by: ipMalVendors, as_owner: ipAttrs.as_owner, country: ipAttrs.country },
          });
        } else if (ipMal > 0 || ipSusp > 0) {
          findings.push({
            module: 'virustotal',
            severity: 'medium',
            title_lt: `IP adresas ${ip} turi reputacijos įspėjimų`,
            description_lt: `IP ${ip} turi ${ipMal} kenkėjiškų ir ${ipSusp} įtartinų pažymėjimų. ISP: ${ipAttrs.as_owner || '?'}, šalis: ${ipAttrs.country || '?'}.`,
            recommendation_lt: 'Stebėkite situaciją.',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { ip, domain, malicious: ipMal, suspicious: ipSusp, as_owner: ipAttrs.as_owner, country: ipAttrs.country },
          });
        }
      } catch { /* non-critical */ }
    }

    // ── 3. URL scan ──────────────────────────────────────────────────
    try {
      const urlToScan = `https://${domain}/`;
      const submitRes = await fetchWithTimeout(
        'https://www.virustotal.com/api/v3/urls',
        {
          method: 'POST',
          headers: { ...vtHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `url=${encodeURIComponent(urlToScan)}`,
        },
        10_000,
      );

      if (submitRes.ok) {
        const submitData = await submitRes.json();
        const analysisId = submitData.data?.id;
        if (analysisId) {
          await new Promise((r) => setTimeout(r, 5000));
          const aRes = await fetchWithTimeout(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers: vtHeaders }, 10_000,
          );
          if (aRes.ok) {
            const aData = await aRes.json();
            const stats = aData.data?.attributes?.stats || {};
            const urlMal = stats.malicious || 0;
            const urlSusp = stats.suspicious || 0;
            if (urlMal > 0 || urlSusp > 0) {
              findings.push({
                module: 'virustotal',
                severity: urlMal >= 3 ? 'critical' : urlMal > 0 ? 'high' : 'medium',
                title_lt: `URL skenavimas: ${urlMal} kenkėjiški, ${urlSusp} įtartini verdiktai`,
                description_lt: `Naujausias URL skenavimas (${urlToScan}) parodė ${urlMal} kenkėjiškų ir ${urlSusp} įtartinų verdiktų.`,
                recommendation_lt: 'Patikrinkite svetainės turinį ir pašalinkite kenkėjišką kodą.',
                nis2_article: '11 str. 2 d. 5 p.',
                evidence: { domain, url: urlToScan, url_malicious: urlMal, url_suspicious: urlSusp, analysis_id: analysisId },
              });
            }
          }
        }
      }
    } catch { /* non-critical */ }

    // ── All clean ────────────────────────────────────────────────────
    if (findings.length === 0) {
      findings.push({
        module: 'virustotal',
        severity: 'info',
        title_lt: 'VirusTotal — domeno reputacija švari',
        description_lt:
          `Domenas ${domain} patikrintas ${totalEngines} saugumo variklių — nė vienas nepažymėjo kaip kenkėjišką.\n` +
          `${reputation !== null ? `Reputacija: ${reputation}\n` : ''}` +
          `${vtSubdomains.length > 0 ? `VT subdomenai: ${vtSubdomains.slice(0, 10).join(', ')}\n` : ''}` +
          `Komunikuojančių kenkėjiškų programų: 0. Platinamų kenkėjiškų failų: 0.`,
        recommendation_lt: 'Jokių veiksmų nereikia.',
        nis2_article: null,
        evidence: {
          domain, malicious_count: 0, suspicious_count: 0, total_engines: totalEngines,
          reputation, communicating_files: 0, downloaded_files: 0,
          vt_subdomains: vtSubdomains, categories,
        },
      });
    }

    return { module: 'virustotal', success: true, findings };
  } catch (err) {
    return { module: 'virustotal', success: false, findings: [], error: err instanceof Error ? err.message : 'Unknown error' };
  }
}
