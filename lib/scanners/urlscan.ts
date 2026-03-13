import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

/**
 * URLScan.io scanner — checks for lookalike domains, phishing detection.
 * Severity: Critical if active phishing detected.
 * KSĮ: Art. 11(2)(b) — incidentų valdymas
 */
export async function scanUrlscan(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.URLSCAN_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'urlscan', success: false, findings: [], error: 'URLSCAN_API_KEY not configured' };
  }

  try {
    // Search for existing scans of this domain
    const searchUrl = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`;
    console.log(`[urlscan] GET ${searchUrl}`);
    const searchRes = await fetchWithTimeout(
      searchUrl,
      {
        headers: { 'API-Key': apiKey },
      },
      15_000,
    );

    console.log(`[urlscan] Response: ${searchRes.status}`);
    if (!searchRes.ok) {
      const errBody = await searchRes.text().catch(() => '');
      console.error(`[urlscan] Error: ${errBody.slice(0, 300)}`);
      return { module: 'urlscan', success: false, findings: [], error: `URLScan API returned: ${searchRes.status}` };
    }

    const searchData = await searchRes.json();
    const findings: ScannerFinding[] = [];
    const results = searchData.results || [];

    // Check for malicious verdicts in existing scans
    let maliciousCount = 0;
    const maliciousUrls: string[] = [];

    for (const result of results) {
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
        title_lt: `Aptikta sukčiavimo / kenkėjiška veikla — ${maliciousCount} aptikimai`,
        description_lt: `URLScan.io duomenų bazėje domenas ${domain} pažymėtas kaip kenkėjiškas ${maliciousCount} skenavimų metu. Tai gali reikšti, kad domenas buvo panaudotas sukčiavimui apsimetant (phishing) arba kenkėjiškos programinės įrangos platinimui. Pažymėti URL: ${maliciousUrls.slice(0, 5).join(', ')}`,
        recommendation_lt: 'Nedelsiant ištirkite pažymėtus URL adresus. Jei svetainė buvo pažeista — nedelsiant pašalinkite kenkėjišką turinį ir pakeiskite visus slaptažodžius.',
        nis2_article: '11 str. 2 d. 2 p.',
        evidence: { domain, malicious_count: maliciousCount, malicious_urls: maliciousUrls, total_scans: results.length },
      });
    }

    // Search for lookalike domains (typosquatting)
    const baseName = domain.split('.')[0];
    if (baseName.length >= 4) {
      const lookalikeRes = await fetchWithTimeout(
        `https://urlscan.io/api/v1/search/?q=domain:*${encodeURIComponent(baseName)}*%20AND%20NOT%20domain:${encodeURIComponent(domain)}&size=10`,
        {
          headers: { 'API-Key': apiKey },
        },
        15_000,
      );

      if (lookalikeRes.ok) {
        const lookalikeData = await lookalikeRes.json();
        const lookalikes = lookalikeData.results || [];

        // Filter for actually similar domains
        const allDomains: string[] = lookalikes
          .map((r: { page?: { domain?: string } }) => r.page?.domain)
          .filter((d: string | undefined): d is string => !!d && d !== domain);
        const similarDomains = Array.from(new Set(allDomains)).slice(0, 10);

        if (similarDomains.length > 0) {
          findings.push({
            module: 'urlscan',
            severity: 'medium',
            title_lt: `Rasti panašūs domenai — galimas sukčiavimas apsimetant`,
            description_lt: `Rasti ${similarDomains.length} domenai, panašūs į ${domain}: ${(similarDomains as string[]).join(', ')}. Tai gali būti typosquatting (rašybos klaidų domenai) arba sukčiavimo apsimetant (phishing) bandymai, kai piktavaliai naudoja panašius domenus, kad apgautų jūsų klientus ar darbuotojus.`,
            recommendation_lt: 'Patikrinkite kiekvieną panašų domeną. Jei tai sukčiavimas — praneškite CERT-LT ir domeno registratoriui.',
            nis2_article: '11 str. 2 d. 2 p.',
            evidence: { domain, lookalike_domains: similarDomains },
          });
        }
      }
    }

    if (findings.length === 0) {
      findings.push({
        module: 'urlscan',
        severity: 'info',
        title_lt: 'URLScan — sukčiavimo veiklos neaptikta',
        description_lt:
          `Domenas ${domain} patikrintas URLScan.io duomenų bazėje ir neturi jokių kenkėjiškų ar sukčiavimo (phishing) pažymėjimų. ` +
          `Tai reiškia, kad jūsų domenas nėra naudojamas kenkėjiškai veiklai ir nebuvo aptiktų sukčiavimo svetainių, susietų su jūsų organizacija.\n\n` +
          `Taip pat nerasta „panašių domenų" (typosquatting), kuriuos piktavaliai galėtų naudoti apsimetant jūsų organizacija.`,
        recommendation_lt: 'Jokių veiksmų nereikia. Periodiškai tikrinkite, ar nepasirodė panašūs domenai, kuriais galėtų apgaudinėti jūsų klientus.',
        nis2_article: null,
        evidence: { domain, total_scans: results.length },
      });
    }

    return { module: 'urlscan', success: true, findings };
  } catch (err) {
    return {
      module: 'urlscan',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
