import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

/**
 * VirusTotal scanner — checks domain/IP reputation, malware associations.
 * Severity: Critical if flagged by 3+ vendors.
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
export async function scanVirustotal(domain: string): Promise<ScannerResult> {
  // Read at call time to ensure env vars are available in serverless
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'virustotal', success: false, findings: [], error: 'VIRUSTOTAL_API_KEY not configured' };
  }

  try {
    const url = `https://www.virustotal.com/api/v3/domains/${domain}`;
    console.log(`[virustotal] GET ${url} (key length: ${apiKey.length})`);
    const res = await fetchWithTimeout(
      url,
      {
        headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
      },
      15_000,
    );

    console.log(`[virustotal] Response: ${res.status}`);
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      console.error(`[virustotal] Error: ${errBody.slice(0, 300)}`);
      return { module: 'virustotal', success: false, findings: [], error: `VirusTotal API returned: ${res.status}` };
    }

    const data = await res.json();
    const findings: ScannerFinding[] = [];

    const attributes = data.data?.attributes || {};
    const lastAnalysis = attributes.last_analysis_stats || {};
    const malicious = lastAnalysis.malicious || 0;
    const suspicious = lastAnalysis.suspicious || 0;
    const totalEngines = (lastAnalysis.harmless || 0) + (lastAnalysis.malicious || 0) +
      (lastAnalysis.suspicious || 0) + (lastAnalysis.undetected || 0);

    if (malicious >= 3) {
      // Get names of vendors that flagged it
      const lastResults = attributes.last_analysis_results || {};
      const flaggedBy = Object.entries(lastResults)
        .filter(([, result]) => (result as { category: string }).category === 'malicious')
        .map(([vendor]) => vendor)
        .slice(0, 10);

      findings.push({
        module: 'virustotal',
        severity: 'critical',
        title_lt: `Domenas pažymėtas kaip kenkėjiškas — ${malicious} saugumo variklių`,
        description_lt: `Domenas ${domain} buvo pažymėtas kaip kenkėjiškas ${malicious} iš ${totalEngines} saugumo variklių (tarp jų: ${flaggedBy.join(', ')}). Tai gali reikšti, kad domenas buvo panaudotas kenkėjiškos programinės įrangos platinimui, sukčiavimui ar kitai neteisėtai veiklai.`,
        recommendation_lt: 'Nedelsiant ištirkite priežastis. Patikrinkite, ar serveris nebuvo pažeistas. Kreipkitės į pažymėjusius tiekėjus dėl domeno reputacijos atkūrimo.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, malicious_count: malicious, suspicious_count: suspicious, total_engines: totalEngines, flagged_by: flaggedBy },
      });
    } else if (malicious > 0 || suspicious > 0) {
      findings.push({
        module: 'virustotal',
        severity: 'high',
        title_lt: `Domeno reputacijos įspėjimai — ${malicious} kenkėjiški, ${suspicious} įtartini`,
        description_lt: `Domenas ${domain} turi ${malicious} kenkėjiškų ir ${suspicious} įtartinų pažymėjimų iš ${totalEngines} saugumo variklių. Nors skaičius mažas, tai gali rodyti pradines reputacijos problemas.`,
        recommendation_lt: 'Patikrinkite domeno turinį ir serverio konfigūraciją. Įsitikinkite, kad svetainė neplatina kenkėjiškos programinės įrangos.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, malicious_count: malicious, suspicious_count: suspicious, total_engines: totalEngines },
      });
    }

    // Check reputation score
    const reputation = attributes.reputation;
    if (typeof reputation === 'number' && reputation < -5) {
      findings.push({
        module: 'virustotal',
        severity: 'medium',
        title_lt: `Neigiama domeno reputacija: ${reputation}`,
        description_lt: `Domeno ${domain} reputacijos balas VirusTotal sistemoje yra ${reputation}. Neigiamas balas rodo, kad bendruomenė pažymėjo šį domeną kaip potencialiai problematišką.`,
        recommendation_lt: 'Peržiūrėkite domeno turinį ir ištirkite galimas reputacijos problemos priežastis.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, reputation },
      });
    }

    if (findings.length === 0) {
      findings.push({
        module: 'virustotal',
        severity: 'info',
        title_lt: 'VirusTotal — domeno reputacija švari',
        description_lt:
          `Domenas ${domain} patikrintas ${totalEngines} saugumo variklių (antivirusinių programų ir saugumo tiekėjų) ir nė vienas iš jų nepažymėjo jo kaip kenkėjiško ar įtartino. ` +
          `Tai reiškia, kad jūsų domenas nėra siejamas su kenkėjiška programine įranga, sukčiavimu ar kitomis grėsmėmis.\n\n` +
          `Tai svarbu, nes blogas domeno reputacija gali sukelti el. laiškų blokavimą, ` +
          `naršyklių perspėjimus lankytojams ir partnerių nepasitikėjimą.`,
        recommendation_lt: 'Jokių veiksmų nereikia. Domeno reputacija puiki.',
        nis2_article: null,
        evidence: { domain, malicious_count: 0, suspicious_count: 0, total_engines: totalEngines },
      });
    }

    return { module: 'virustotal', success: true, findings };
  } catch (err) {
    return {
      module: 'virustotal',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
