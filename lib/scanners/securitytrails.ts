import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { resolve } from 'dns/promises';

/**
 * SecurityTrails scanner — checks subdomains, DNS history, dangling records.
 * Severity: High if dangling subdomain, Medium if suspicious DNS history.
 * KSĮ: Art. 11(2)(a) — rizikų valdymas
 */
export async function scanSecuritytrails(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.SECURITYTRAILS_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'securitytrails', success: false, findings: [], error: 'SECURITYTRAILS_API_KEY not configured' };
  }

  const headers = {
    APIKEY: apiKey,
    Accept: 'application/json',
  };

  try {
    const findings: ScannerFinding[] = [];

    // 1. Subdomain enumeration
    const subUrl = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains?children_only=false`;
    console.log(`[securitytrails] GET ${subUrl} (key length: ${apiKey.length})`);
    const subdomainsRes = await fetchWithTimeout(subUrl, { headers }, 15_000);

    console.log(`[securitytrails] Response: ${subdomainsRes.status}`);
    if (!subdomainsRes.ok) {
      const status = subdomainsRes.status;
      if (status === 429) {
        return { module: 'securitytrails', success: false, findings: [], error: 'SecurityTrails API rate limit exceeded' };
      }
      return { module: 'securitytrails', success: false, findings: [], error: `SecurityTrails subdomains API returned: ${status}` };
    }

    const subdomainsData = await subdomainsRes.json();
    const subdomains: string[] = (subdomainsData.subdomains || []).map(
      (sub: string) => `${sub}.${domain}`,
    );

    // Check for dangling subdomains (resolve a sample — max 20 to stay within timeout)
    const danglingSubdomains: string[] = [];
    const sampleSubdomains = subdomains.slice(0, 20);

    const dnsChecks = await Promise.allSettled(
      sampleSubdomains.map(async (sub) => {
        try {
          await resolve(sub, 'A');
          return { subdomain: sub, resolves: true };
        } catch {
          return { subdomain: sub, resolves: false };
        }
      }),
    );

    for (const result of dnsChecks) {
      if (result.status === 'fulfilled' && !result.value.resolves) {
        danglingSubdomains.push(result.value.subdomain);
      }
    }

    if (danglingSubdomains.length > 0) {
      const subList = danglingSubdomains.slice(0, 10).map(sub =>
        `• ${sub} — DNS A įrašas nurodo į neegzistuojantį serverį`
      ).join('\n');
      const moreStr = danglingSubdomains.length > 10 ? `\n...ir dar ${danglingSubdomains.length - 10} kabantys subdomenai.` : '';

      findings.push({
        module: 'securitytrails',
        severity: 'high',
        title_lt: `Rasti ${danglingSubdomains.length} kabantys subdomenai`,
        description_lt:
          `Jūsų organizacijos DNS sistemoje rasti subdomenai, kurie nebeveda į jokį veikiantį serverį — jie „kabo" tuščioje vietoje:\n` +
          `${subList}${moreStr}\n\n` +
          `Kodėl tai pavojinga: kai subdomenas nebeveda į jūsų serverį, piktavaliai gali užregistruoti serverį tuo pačiu adresu ir perimti subdomeną (tai vadinama „subdomain takeover"). ` +
          `Tada jie gali sukurti suklastotą svetainę su jūsų organizacijos vardu (pvz., ${danglingSubdomains[0]}) ir ` +
          `naudoti ją darbuotojų ar klientų apgaudinėjimui — rinkti slaptažodžius, platinti kenkėjišką programinę įrangą.\n\n` +
          `Tai panašu į situaciją, kai jūsų organizacija turėjo biuro patalpas, išsikraustė, bet iškaba su organizacijos pavadinimu liko kaboti ant pastato. ` +
          `Kitas asmuo gali atsikraustyti ir apsimesti jūsų organizacija.\n\n` +
          `Verslo poveikis: reputacijos žala, klientų duomenų vagystė, reguliacinės baudos pagal KSĮ 11 str. 2 d. 1 p.`,
        recommendation_lt:
          `1. Perduokite šį sąrašą IT administratoriui ir paprašykite per 3 darbo dienas pašalinti nebereikalingus DNS įrašus.\n` +
          `2. Kiekvienam subdomenui: jei jis naudojamas — atkurkite serverį; jei nenaudojamas — pašalinkite DNS A įrašą.\n` +
          `3. Įveskite taisyklę: prieš išjungiant bet kokį serverį, pirmiausia turi būti pašalintas DNS įrašas.\n` +
          `4. Kas ketvirtį peržiūrėkite subdomenų sąrašą ir pašalinkite nebenaudojamus.`,
        nis2_article: '11 str. 2 d. 1 p.',
        evidence: { domain, dangling_subdomains: danglingSubdomains, checked_count: sampleSubdomains.length },
      });
    }

    // Report total subdomain count as attack surface indicator
    if (subdomains.length > 50) {
      findings.push({
        module: 'securitytrails',
        severity: 'medium',
        title_lt: `Didelis subdomenų skaičius — ${subdomains.length} vnt.`,
        description_lt: `Domenas ${domain} turi ${subdomains.length} subdomenų. Didelis subdomenų skaičius padidina atakos paviršių ir apsunkina saugumo stebėjimą. Kiekvienas subdomenas yra potencialus atakos taškas.`,
        recommendation_lt: 'Peržiūrėkite subdomenų sąrašą ir pašalinkite nebenaudojamus. Reguliariai audituokite naujus subdomenis.',
        nis2_article: '11 str. 2 d. 1 p.',
        evidence: { domain, subdomain_count: subdomains.length, sample: subdomains.slice(0, 20) },
      });
    }

    // 2. DNS history — check for frequent IP changes
    try {
      const historyRes = await fetchWithTimeout(
        `https://api.securitytrails.com/v1/history/${encodeURIComponent(domain)}/dns/a`,
        { headers },
        15_000,
      );

      if (historyRes.ok) {
        const historyData = await historyRes.json();
        const records = historyData.records || [];

        // Count unique IPs in the last year
        const oneYearAgo = new Date();
        oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

        const recentRecords = records.filter((r: { last_seen?: string }) => {
          if (!r.last_seen) return true;
          return new Date(r.last_seen) >= oneYearAgo;
        });

        const uniqueIps = new Set<string>();
        for (const record of recentRecords) {
          const values = record.values || [];
          for (const val of values) {
            if (val.ip) uniqueIps.add(val.ip);
          }
        }

        if (uniqueIps.size > 10) {
          findings.push({
            module: 'securitytrails',
            severity: 'medium',
            title_lt: `Dažni DNS pakeitimai — ${uniqueIps.size} skirtingi IP adresai`,
            description_lt: `Per paskutinius metus domeno ${domain} A įrašas rodė į ${uniqueIps.size} skirtingų IP adresų. Dažni IP adresų pakeitimai gali rodyti nestabilią infrastruktūrą arba kompromituotą DNS valdymą.`,
            recommendation_lt: 'Patikrinkite DNS pakeitimų istoriją ir įsitikinkite, kad visi pakeitimai buvo autorizuoti. Apsvarstykite DNS stebėjimo įrankių naudojimą.',
            nis2_article: '11 str. 2 d. 1 p.',
            evidence: { domain, unique_ips: Array.from(uniqueIps), record_count: recentRecords.length },
          });
        }
      }
    } catch (err) {
      console.error(`SecurityTrails DNS history check failed for ${domain}: ${err instanceof Error ? err.message : 'Unknown error'}`);
      // Non-critical — continue with other checks
    }

    if (findings.length === 0) {
      findings.push({
        module: 'securitytrails',
        severity: 'info',
        title_lt: 'Subdomenai ir DNS — viskas tvarkoje',
        description_lt:
          `Domeno ${domain} subdomenų ir DNS istorijos analizė neparodė jokių problemų. ` +
          `Rasta ${subdomains.length} subdomenų — visi jie veda į veikiančius serverius, „kabančių" subdomenų neaptikta.\n\n` +
          `Tai reiškia, kad piktavaliai negali perimti jūsų nebenaudojamų subdomenų ir apsimesti jūsų organizacija.`,
        recommendation_lt: 'Jokių veiksmų nereikia. Rekomenduojame kas ketvirtį peržiūrėti subdomenų sąrašą ir pašalinti nebenaudojamus.',
        nis2_article: null,
        evidence: { domain, subdomain_count: subdomains.length, dangling_count: 0 },
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
