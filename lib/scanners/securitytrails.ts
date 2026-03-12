import type { ScannerResult, ScannerFinding } from './types';

const SECURITYTRAILS_API_KEY = process.env.SECURITYTRAILS_API_KEY;

/**
 * SecurityTrails scanner — checks subdomains, DNS history, dangling records.
 * Severity: High if dangling subdomain, Medium if suspicious history.
 * KSĮ: Art. 11(2)(a) — rizikų valdymas
 */
export async function scanSecuritytrails(domain: string): Promise<ScannerResult> {
  if (!SECURITYTRAILS_API_KEY) {
    return { module: 'securitytrails', success: false, findings: [], error: 'SECURITYTRAILS_API_KEY not configured' };
  }

  try {
    const findings: ScannerFinding[] = [];

    // Get subdomains
    const subdomainRes = await fetch(
      `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`,
      {
        headers: { APIKEY: SECURITYTRAILS_API_KEY, Accept: 'application/json' },
      },
    );

    if (!subdomainRes.ok) {
      return { module: 'securitytrails', success: false, findings: [], error: `SecurityTrails API returned: ${subdomainRes.status}` };
    }

    const subdomainData = await subdomainRes.json();
    const subdomains: string[] = (subdomainData.subdomains || []).map((s: string) => `${s}.${domain}`);

    if (subdomains.length > 50) {
      findings.push({
        module: 'securitytrails',
        severity: 'medium',
        title_lt: `Didelis subdomenų skaičius — ${subdomains.length}`,
        description_lt: `Domenas ${domain} turi ${subdomains.length} subdomenų. Didelis subdomenų skaičius padidina atakos paviršių ir apsunkina visų domenų saugumo priežiūrą. Kiekvienas neprižiūrimas subdomenas gali tapti atakos tašku.`,
        recommendation_lt: 'Peržiūrėkite subdomenų sąrašą ir pašalinkite nebereikalingus. Reguliariai audituokite aktyvius subdomenus.',
        nis2_article: '11 str. 2 d. 1 p.',
        evidence: { domain, subdomain_count: subdomains.length, subdomains: subdomains.slice(0, 50) },
      });
    }

    // Check for potentially dangling subdomains (common patterns)
    const danglingPatterns = ['staging', 'dev', 'test', 'old', 'legacy', 'temp', 'demo', 'beta', 'backup'];
    const potentiallyDangling = subdomains.filter((s: string) =>
      danglingPatterns.some((p) => s.toLowerCase().includes(p)),
    );

    if (potentiallyDangling.length > 0) {
      findings.push({
        module: 'securitytrails',
        severity: 'high',
        title_lt: `Galimi „kabantys" subdomenai — ${potentiallyDangling.length}`,
        description_lt: `Rasti subdomenai, kurie gali būti nebeprižiūrimi ar palikti be priežiūros: ${potentiallyDangling.slice(0, 10).join(', ')}. „Kabantys" subdomenai (dangling DNS) gali būti perimti piktavalių ir panaudoti sukčiavimui ar kenkėjiškos programinės įrangos platinimui.`,
        recommendation_lt: 'Patikrinkite kiekvieną iš šių subdomenų. Jei jie nebereikalingi — pašalinkite DNS įrašus. Jei aktyvūs — įsitikinkite, kad jie tinkamai apsaugoti.',
        nis2_article: '11 str. 2 d. 1 p.',
        evidence: { domain, dangling_candidates: potentiallyDangling },
      });
    }

    // Get DNS history
    const historyRes = await fetch(
      `https://api.securitytrails.com/v1/history/${encodeURIComponent(domain)}/dns/a`,
      {
        headers: { APIKEY: SECURITYTRAILS_API_KEY, Accept: 'application/json' },
      },
    );

    if (historyRes.ok) {
      const historyData = await historyRes.json();
      const records = historyData.records || [];

      if (records.length > 10) {
        findings.push({
          module: 'securitytrails',
          severity: 'low',
          title_lt: `Dažni DNS pakeitimai — ${records.length} istoriniai įrašai`,
          description_lt: `Domeno ${domain} DNS A įrašas buvo keistas ${records.length} kartų. Dažni DNS pakeitimai gali rodyti nestabilią infrastruktūrą arba praeityje buvusias problemas.`,
          recommendation_lt: 'Peržiūrėkite DNS pakeitimų istoriją ir įsitikinkite, kad visi pakeitimai buvo autorizuoti.',
          nis2_article: '11 str. 2 d. 1 p.',
          evidence: { domain, dns_changes: records.length, recent_records: records.slice(0, 5) },
        });
      }
    }

    if (findings.length === 0) {
      findings.push({
        module: 'securitytrails',
        severity: 'info',
        title_lt: 'Subdomenų ir DNS analizė — problemų nerasta',
        description_lt: `Domeno ${domain} subdomenų ir DNS istorijos analizė neparodė rimtų problemų. Rasta ${subdomains.length} subdomenų.`,
        recommendation_lt: 'Tęskite periodinį subdomenų stebėjimą.',
        nis2_article: null,
        evidence: { domain, subdomain_count: subdomains.length },
      });
    }

    return { module: 'securitytrails', success: true, findings };
  } catch (err) {
    return {
      module: 'securitytrails',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
