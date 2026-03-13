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
      findings.push({
        module: 'securitytrails',
        severity: 'high',
        title_lt: `Rasti ${danglingSubdomains.length} kabantys subdomenai`,
        description_lt: `Aptikti subdomenai, kurie nebeturi veikiančio DNS A įrašo: ${danglingSubdomains.slice(0, 10).join(', ')}${danglingSubdomains.length > 10 ? ` ir dar ${danglingSubdomains.length - 10}` : ''}. Kabantys subdomenai gali būti perimti piktavalių (subdomain takeover) ir panaudoti sukčiavimui ar kenkėjiškos programinės įrangos platinimui.`,
        recommendation_lt: 'Pašalinkite nebenaudojamų subdomenų DNS įrašus. Jei subdomenai turėtų veikti — atkurkite jų A įrašus.',
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
      console.error(`SecurityTrails DNS history check failed for ${domain}:`, err);
      // Non-critical — continue with other checks
    }

    if (findings.length === 0) {
      findings.push({
        module: 'securitytrails',
        severity: 'info',
        title_lt: 'SecurityTrails — problemų nerasta',
        description_lt: `Domeno ${domain} subdomenų ir DNS istorijos analizė neparodė kritinių ar aukštų rizikų. Rasta ${subdomains.length} subdomenų, kabančių subdomenų neaptikta.`,
        recommendation_lt: 'Tęskite periodinį stebėjimą.',
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
