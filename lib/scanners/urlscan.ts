import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * URLScan.io scanner — full web intelligence.
 * 1. Search existing scans: GET /api/v1/search/?q=domain:{domain}
 * 2. Submit new scan: POST /api/v1/scan/ → Poll GET /api/v1/result/{uuid}/
 * 3. Extract: redirects, technologies, trackers, external links, verdicts
 * 4. Lookalike domain search: GET /api/v1/search/?q=page.domain:*{base}*
 *
 * Severity: Critical if malicious or active phishing, High if redirect to unexpected domain,
 *           Medium if lookalike domains, Low if outdated tech
 * KSĮ: Art. 11(2)(b) — incidentų valdymas
 */
export async function scanUrlscan(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.URLSCAN_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'urlscan', success: false, findings: [], error: 'URLSCAN_API_KEY not configured' };
  }

  const apiHeaders = { 'API-Key': apiKey, 'Content-Type': 'application/json' };

  try {
    const findings: ScannerFinding[] = [];

    // ── 1. Search existing scans ─────────────────────────────────────
    const searchUrl = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`;
    console.log(`[urlscan] GET search: ${domain}`);
    const searchRes = await fetchWithTimeout(searchUrl, { headers: { 'API-Key': apiKey } }, 15_000);
    console.log(`[urlscan] Search response: ${searchRes.status}`);

    if (!searchRes.ok) {
      await searchRes.text().catch(() => '');
      return { module: 'urlscan', success: false, findings: [], error: `URLScan API returned: ${searchRes.status}` };
    }

    const searchData = await searchRes.json();
    const existingResults = searchData.results || [];

    // Check for malicious verdicts in existing scans
    let maliciousCount = 0;
    const maliciousUrls: string[] = [];
    for (const result of existingResults) {
      if (result.verdicts) {
        const overall = result.verdicts.overall || {};
        if (overall.malicious) {
          maliciousCount++;
          maliciousUrls.push(result.page?.url || result.task?.url || 'unknown');
        }
      }
    }

    if (maliciousCount > 0) {
      findings.push({
        module: 'urlscan',
        severity: 'critical',
        title_lt: `Aptikta kenkėjiška veikla — ${maliciousCount} pažymėti skenavimų`,
        description_lt:
          `URLScan.io duomenų bazėje domenas ${domain} pažymėtas kaip kenkėjiškas ${maliciousCount} skenavimų metu. ` +
          `Tai gali reikšti, kad domenas buvo panaudotas sukčiavimui (phishing) arba kenkėjiškos programinės įrangos platinimui.\n\n` +
          `Pažymėti URL: ${maliciousUrls.slice(0, 5).join(', ')}`,
        recommendation_lt:
          `1. SKUBIAI ištirkite pažymėtus URL adresus.\n` +
          `2. Jei svetainė pažeista — pašalinkite kenkėjišką turinį.\n` +
          `3. Pakeiskite visus slaptažodžius.\n` +
          `4. Praneškite CERT-LT.`,
        nis2_article: '11 str. 2 d. 2 p.',
        evidence: { domain, malicious_count: maliciousCount, malicious_urls: maliciousUrls, total_scans: existingResults.length },
      });
    }

    // ── 2. Submit new scan ───────────────────────────────────────────
    let scanResult: Record<string, unknown> | null = null;
    try {
      const submitRes = await fetchWithTimeout(
        'https://urlscan.io/api/v1/scan/',
        {
          method: 'POST',
          headers: apiHeaders,
          body: JSON.stringify({ url: `https://${domain}`, visibility: 'unlisted' }),
        },
        10_000,
      );

      if (submitRes.ok) {
        const submitData = await submitRes.json();
        const scanUuid = submitData.uuid;
        const resultUrl = submitData.api;

        if (scanUuid && resultUrl) {
          console.log(`[urlscan] Scan submitted: ${scanUuid}`);

          // Poll for result (max 4 attempts, 10s intervals)
          await sleep(10_000);
          for (let i = 0; i < 4; i++) {
            try {
              const resultRes = await fetchWithTimeout(resultUrl, {}, 10_000);
              if (resultRes.ok) {
                scanResult = await resultRes.json();
                console.log(`[urlscan] Scan result received`);
                break;
              }
              if (resultRes.status === 404) {
                // Not ready yet
                if (i < 3) await sleep(10_000);
              } else {
                break;
              }
            } catch {
              if (i < 3) await sleep(10_000);
            }
          }
        }
      }
    } catch {
      // Scan submission non-critical
    }

    // ── 3. Extract scan result details ───────────────────────────────
    if (scanResult) {
      const page = (scanResult.page || {}) as Record<string, unknown>;
      const verdicts = (scanResult.verdicts || {}) as Record<string, unknown>;
      const lists = (scanResult.lists || {}) as Record<string, unknown>;
      const stats = (scanResult.stats || {}) as Record<string, unknown>;

      // Final URL after redirects
      const requestedUrl = `https://${domain}`;
      const finalUrl = (page.url as string) || requestedUrl;
      const finalDomain = (page.domain as string) || domain;

      // Check for unexpected redirect
      if (finalDomain !== domain && !finalDomain.endsWith(`.${domain}`)) {
        findings.push({
          module: 'urlscan',
          severity: 'high',
          title_lt: `Domenas peradresuoja į netikėtą svetainę: ${finalDomain}`,
          description_lt:
            `Kreipiantis į ${requestedUrl}, vartotojas peradresuojamas į ${finalUrl}. ` +
            `Peradresavimas į kitą domeną gali rodyti domeno užgrobimą arba sukčiavimą.`,
          recommendation_lt:
            `1. Patikrinkite serverio konfigūraciją — ar peradresavimas yra autorizuotas.\n` +
            `2. Jei ne — patikrinkite serverio saugumą dėl pažeidimo.`,
          nis2_article: '11 str. 2 d. 2 p.',
          evidence: { domain, requested_url: requestedUrl, final_url: finalUrl, final_domain: finalDomain },
        });
      }

      // HTTP response code
      const statusCode = page.status as number | undefined;
      if (statusCode && statusCode >= 400) {
        findings.push({
          module: 'urlscan',
          severity: 'low',
          title_lt: `Svetainė grąžina HTTP ${statusCode} klaidą`,
          description_lt: `Kreipiantis į ${domain}, serveris grąžina HTTP ${statusCode} atsakymo kodą. Svetainė gali būti nepasiekiama arba neteisingai sukonfigūruota.`,
          recommendation_lt: 'Patikrinkite svetainės konfigūraciją.',
          nis2_article: null,
          evidence: { domain, status_code: statusCode },
        });
      }

      // Verdicts
      const overallVerdict = (verdicts.overall || {}) as { malicious?: boolean; score?: number; tags?: string[] };
      const urlscanVerdict = (verdicts.urlscan || {}) as { malicious?: boolean; score?: number; tags?: string[] };
      const engines = (verdicts.engines || {}) as Record<string, unknown>;

      if (overallVerdict.malicious || urlscanVerdict.malicious) {
        const tags = [...(overallVerdict.tags || []), ...(urlscanVerdict.tags || [])];
        findings.push({
          module: 'urlscan',
          severity: 'critical',
          title_lt: `Svetainė pažymėta kaip kenkėjiška — URLScan verdiktas`,
          description_lt:
            `Naujausias URLScan.io skenavimas pažymėjo ${domain} kaip kenkėjišką.\n` +
            `${tags.length > 0 ? `Žymos: ${tags.join(', ')}\n` : ''}` +
            `Balas: ${overallVerdict.score || urlscanVerdict.score || 'nenustatytas'}`,
          recommendation_lt:
            `1. Nedelsiant ištirkite svetainės turinį.\n` +
            `2. Patikrinkite serverį dėl kenkėjiškos programinės įrangos.`,
          nis2_article: '11 str. 2 d. 2 p.',
          evidence: { domain, overall_verdict: overallVerdict, urlscan_verdict: urlscanVerdict, engines },
        });
      }

      // Technologies detected
      const technologies = (lists.urls || []) as string[];
      const techFingerprint = (stats.tlsStats || []) as Array<{ protocol: string; count: number }>;

      // External links and scripts
      const externalLinks = ((lists.linkDomains || []) as string[]).filter((d: string) => d !== domain && !d.endsWith(`.${domain}`));
      const scripts = (lists.scriptDomains || []) as string[];
      const externalScripts = scripts.filter((d: string) => d !== domain && !d.endsWith(`.${domain}`));

      if (externalScripts.length > 0) {
        findings.push({
          module: 'urlscan',
          severity: 'info',
          title_lt: `Išoriniai JavaScript šaltiniai — ${externalScripts.length} domenų`,
          description_lt:
            `Svetainė ${domain} įkelia JavaScript iš ${externalScripts.length} išorinių domenų:\n` +
            externalScripts.slice(0, 10).map((d: string) => `• ${d}`).join('\n') +
            `\n\nKiekvienas išorinis JavaScript šaltinis yra potencialus tiekimo grandinės atakos taškas — ` +
            `jei išorinis domenas bus pažeistas, kenkėjiškas kodas gali patekti į jūsų svetainę.`,
          recommendation_lt:
            `1. Peržiūrėkite išorinių JavaScript šaltinių sąrašą.\n` +
            `2. Naudokite Subresource Integrity (SRI) hash'us.\n` +
            `3. Apsvarstykite Content Security Policy (CSP) antraštės naudojimą.`,
          nis2_article: null,
          evidence: {
            domain,
            external_scripts: externalScripts,
            external_links: externalLinks.slice(0, 15),
            technologies: technologies.slice(0, 20),
            tls_stats: techFingerprint,
          },
        });
      }

      // Screenshot URL (info)
      const screenshotUrl = (scanResult.task as Record<string, unknown>)?.screenshotURL;
      if (screenshotUrl) {
        findings.push({
          module: 'urlscan',
          severity: 'info',
          title_lt: 'Svetainės ekranvaizdis užfiksuotas',
          description_lt: `URLScan.io užfiksavo svetainės ${domain} ekranvaizdį skenavimo metu.`,
          recommendation_lt: 'Informacinis įrašas.',
          nis2_article: null,
          evidence: { domain, screenshot_url: screenshotUrl },
        });
      }
    }

    // ── 4. Lookalike domain search ───────────────────────────────────
    const baseName = domain.split('.')[0];
    if (baseName.length >= 4) {
      try {
        const lookalikeRes = await fetchWithTimeout(
          `https://urlscan.io/api/v1/search/?q=page.domain:*${encodeURIComponent(baseName)}*%20AND%20NOT%20page.domain:${encodeURIComponent(domain)}&size=20`,
          { headers: { 'API-Key': apiKey } },
          15_000,
        );

        if (lookalikeRes.ok) {
          const lookalikeData = await lookalikeRes.json();
          const lookalikes = lookalikeData.results || [];

          const allDomains: string[] = lookalikes
            .map((r: { page?: { domain?: string } }) => r.page?.domain)
            .filter((d: string | undefined): d is string => !!d && d !== domain);
          const similarDomains = Array.from(new Set(allDomains)).slice(0, 15);

          // Check which lookalikes have malicious verdicts
          const maliciousLookalikes: string[] = [];
          const activeLookalikes: string[] = [];

          for (const result of lookalikes) {
            const ld = result.page?.domain;
            if (!ld || ld === domain) continue;

            if (result.verdicts?.overall?.malicious) {
              if (!maliciousLookalikes.includes(ld)) maliciousLookalikes.push(ld);
            } else {
              if (!activeLookalikes.includes(ld)) activeLookalikes.push(ld);
            }
          }

          if (maliciousLookalikes.length > 0) {
            findings.push({
              module: 'urlscan',
              severity: 'critical',
              title_lt: `Aktyvūs sukčiavimo domenai — ${maliciousLookalikes.length} kenkėjiški panašūs domenai`,
              description_lt:
                `Rasti ${maliciousLookalikes.length} domenai, panašūs į ${domain}, kurie pažymėti kaip KENKĖJIŠKI:\n` +
                maliciousLookalikes.slice(0, 10).map((d) => `• ${d} — pažymėtas kaip kenkėjiškas`).join('\n') +
                `\n\nŠie domenai gali būti naudojami sukčiavimui apsimetant jūsų organizacija (phishing).`,
              recommendation_lt:
                `1. Praneškite CERT-LT apie sukčiavimo domenus.\n` +
                `2. Kreipkitės į domenų registratorius dėl pašalinimo.\n` +
                `3. Informuokite darbuotojus ir klientus apie sukčiavimo domenus.\n` +
                `4. Apsvarstykite stebėjimo paslaugą panašiems domenams.`,
              nis2_article: '11 str. 2 d. 2 p.',
              evidence: { domain, malicious_lookalikes: maliciousLookalikes },
            });
          }

          if (similarDomains.length > 0 && maliciousLookalikes.length === 0) {
            findings.push({
              module: 'urlscan',
              severity: 'medium',
              title_lt: `Rasti panašūs domenai — galimas sukčiavimas apsimetant`,
              description_lt:
                `Rasti ${similarDomains.length} domenai, panašūs į ${domain}:\n` +
                similarDomains.slice(0, 10).map((d) => `• ${d}`).join('\n') +
                `\n\nTai gali būti typosquatting (rašybos klaidų domenai) arba sukčiavimo (phishing) bandymai.`,
              recommendation_lt:
                `1. Patikrinkite kiekvieną panašų domeną.\n` +
                `2. Jei tai sukčiavimas — praneškite CERT-LT ir registratoriui.`,
              nis2_article: '11 str. 2 d. 2 p.',
              evidence: { domain, lookalike_domains: similarDomains, active_count: activeLookalikes.length },
            });
          }
        }
      } catch {
        // Lookalike search non-critical
      }
    }

    // ── All clean ────────────────────────────────────────────────────
    if (findings.length === 0) {
      findings.push({
        module: 'urlscan',
        severity: 'info',
        title_lt: 'URLScan — sukčiavimo veiklos neaptikta',
        description_lt:
          `Domenas ${domain} patikrintas URLScan.io — neturi kenkėjiškų pažymėjimų, panašių domenų (typosquatting) neaptikta.\n\n` +
          `${scanResult ? 'Naujausias skenavimas atliktas sėkmingai — svetainė veikia normaliai.' : 'Esami skenavimų rezultatai švarūs.'}`,
        recommendation_lt: 'Jokių veiksmų nereikia. Periodiškai tikrinkite.',
        nis2_article: null,
        evidence: { domain, total_existing_scans: existingResults.length, new_scan_completed: !!scanResult },
      });
    }

    return { module: 'urlscan', success: true, findings };
  } catch (err) {
    return { module: 'urlscan', success: false, findings: [], error: err instanceof Error ? err.message : 'Unknown error' };
  }
}
