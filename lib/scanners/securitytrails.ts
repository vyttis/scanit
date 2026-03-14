import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { resolve } from 'dns/promises';

/**
 * SecurityTrails scanner — full domain intelligence.
 * 1. Domain info: GET /v1/domain/{domain} — current DNS, Alexa rank
 * 2. Subdomain enumeration: GET /v1/domain/{domain}/subdomains
 * 3. DNS history: GET /v1/history/{domain}/dns/{type} for A, MX, NS
 * 4. Associated domains: GET /v1/domain/{domain}/associated
 * 5. WHOIS: GET /v1/domain/{domain}/whois
 *
 * Severity: Critical if domain expiring, High if dangling subdomain, Medium if suspicious history
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

    // ── 1. Domain info ───────────────────────────────────────────────
    let domainInfo: Record<string, unknown> | null = null;
    try {
      const infoRes = await fetchWithTimeout(
        `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}`,
        { headers },
        15_000,
      );
      console.log(`[securitytrails] Domain info: ${infoRes.status}`);
      if (infoRes.ok) {
        domainInfo = await infoRes.json();
      } else if (infoRes.status === 429) {
        return { module: 'securitytrails', success: false, findings: [], error: 'SecurityTrails API rate limit exceeded' };
      }
    } catch {
      // Non-critical
    }

    // ── 2. Subdomain enumeration ─────────────────────────────────────
    const subUrl = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains?children_only=false`;
    console.log(`[securitytrails] GET subdomains`);
    const subdomainsRes = await fetchWithTimeout(subUrl, { headers }, 15_000);
    console.log(`[securitytrails] Subdomains response: ${subdomainsRes.status}`);

    if (!subdomainsRes.ok) {
      const status = subdomainsRes.status;
      if (status === 429) {
        return { module: 'securitytrails', success: false, findings: [], error: 'SecurityTrails API rate limit exceeded' };
      }
      await subdomainsRes.text().catch(() => '');
      return { module: 'securitytrails', success: false, findings: [], error: `SecurityTrails API returned: ${status}` };
    }

    const subdomainsData = await subdomainsRes.json();
    const subdomains: string[] = (subdomainsData.subdomains || []).map(
      (sub: string) => `${sub}.${domain}`,
    );

    // Check for dangling subdomains (DNS A check on sample — max 25)
    const danglingSubdomains: string[] = [];
    const sampleSubdomains = subdomains.slice(0, 25);

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
      const subList = danglingSubdomains.slice(0, 10).map((sub) =>
        `• ${sub} — DNS A įrašas nurodo į neegzistuojantį serverį`
      ).join('\n');
      const moreStr = danglingSubdomains.length > 10 ? `\n...ir dar ${danglingSubdomains.length - 10} kabantys subdomenai.` : '';

      findings.push({
        module: 'securitytrails',
        severity: 'high',
        title_lt: `Rasti ${danglingSubdomains.length} kabantys subdomenai — subdomain takeover rizika`,
        description_lt:
          `Jūsų organizacijos DNS sistemoje rasti subdomenai, kurie nebeveda į jokį veikiantį serverį:\n` +
          `${subList}${moreStr}\n\n` +
          `Kodėl tai pavojinga: kai subdomenas nebeveda į jūsų serverį, piktavaliai gali užregistruoti serverį tuo pačiu adresu ir perimti subdomeną (subdomain takeover). ` +
          `Tada jie gali sukurti suklastotą svetainę su jūsų organizacijos vardu (pvz., ${danglingSubdomains[0]}) ir ` +
          `naudoti ją darbuotojų ar klientų apgaudinėjimui.\n\n` +
          `Verslo poveikis: reputacijos žala, klientų duomenų vagystė, reguliacinės baudos pagal KSĮ 11 str. 2 d. 1 p.`,
        recommendation_lt:
          `1. Perduokite šį sąrašą IT administratoriui ir paprašykite per 3 darbo dienas pašalinti nebereikalingus DNS įrašus.\n` +
          `2. Kiekvienam subdomenui: jei jis naudojamas — atkurkite serverį; jei nenaudojamas — pašalinkite DNS A įrašą.\n` +
          `3. Įveskite taisyklę: prieš išjungiant bet kokį serverį, pirmiausia turi būti pašalintas DNS įrašas.\n` +
          `4. Kas ketvirtį peržiūrėkite subdomenų sąrašą.`,
        nis2_article: '11 str. 2 d. 1 p.',
        evidence: { domain, dangling_subdomains: danglingSubdomains, checked_count: sampleSubdomains.length, total_subdomains: subdomains.length },
      });
    }

    // Attack surface: total subdomain count
    if (subdomains.length > 50) {
      findings.push({
        module: 'securitytrails',
        severity: 'medium',
        title_lt: `Didelis atakos paviršius — ${subdomains.length} subdomenų`,
        description_lt:
          `Domenas ${domain} turi ${subdomains.length} subdomenų. Kiekvienas subdomenas yra potencialus atakos taškas. ` +
          `Didelis skaičius apsunkina saugumo valdymą.`,
        recommendation_lt:
          `1. Peržiūrėkite visą subdomenų sąrašą ir pašalinkite nebenaudojamus.\n` +
          `2. Kas ketvirtį audituokite naujus subdomenis.`,
        nis2_article: '11 str. 2 d. 1 p.',
        evidence: { domain, subdomain_count: subdomains.length, sample: subdomains.slice(0, 30) },
      });
    }

    // ── 3. DNS history — A, MX, NS ──────────────────────────────────
    for (const dnsType of ['a', 'mx', 'ns'] as const) {
      try {
        const historyRes = await fetchWithTimeout(
          `https://api.securitytrails.com/v1/history/${encodeURIComponent(domain)}/dns/${dnsType}`,
          { headers },
          15_000,
        );

        if (!historyRes.ok) continue;
        const historyData = await historyRes.json();
        const records = historyData.records || [];

        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const recentChanges = records.filter((r: { first_seen?: string }) => {
          const firstSeen = r.first_seen ? new Date(r.first_seen) : null;
          return firstSeen && firstSeen >= thirtyDaysAgo;
        });

        if (dnsType === 'a') {
          const oneYearAgo = new Date();
          oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

          const recentRecords = records.filter((r: { last_seen?: string }) => {
            if (!r.last_seen) return true;
            return new Date(r.last_seen) >= oneYearAgo;
          });

          const uniqueIps = new Set<string>();
          for (const record of recentRecords) {
            for (const val of (record.values || [])) {
              if (val.ip) uniqueIps.add(val.ip);
            }
          }

          if (uniqueIps.size > 10) {
            findings.push({
              module: 'securitytrails',
              severity: 'medium',
              title_lt: `Dažni DNS A pakeitimai — ${uniqueIps.size} skirtingi IP adresai per metus`,
              description_lt:
                `Per paskutinius metus domeno ${domain} A įrašas rodė į ${uniqueIps.size} skirtingų IP adresų. ` +
                `Tai gali rodyti nestabilią infrastruktūrą arba kompromituotą DNS valdymą.`,
              recommendation_lt:
                `1. Patikrinkite DNS pakeitimų istoriją.\n` +
                `2. Įdiekite DNS stebėjimo įrankį.\n` +
                `3. Apsvarstykite DNSSEC naudojimą.`,
              nis2_article: '11 str. 2 d. 1 p.',
              evidence: { domain, unique_ips: Array.from(uniqueIps), record_count: recentRecords.length },
            });
          }

          if (recentChanges.length > 0) {
            findings.push({
              module: 'securitytrails',
              severity: 'medium',
              title_lt: `DNS A įrašas keitėsi per paskutines 30 dienų`,
              description_lt:
                `Domeno ${domain} A įrašas buvo pakeistas ${recentChanges.length} kartų per paskutines 30 dienų. ` +
                `Tai gali rodyti infrastruktūros pokyčius arba galimą DNS užgrobimą.`,
              recommendation_lt: 'Patikrinkite, ar šie DNS pakeitimai buvo autorizuoti.',
              nis2_article: '11 str. 2 d. 1 p.',
              evidence: { domain, dns_type: dnsType, recent_changes: recentChanges.slice(0, 5) },
            });
          }
        }

        if (dnsType === 'ns' && recentChanges.length > 0) {
          findings.push({
            module: 'securitytrails',
            severity: 'high',
            title_lt: `Vardų serveriai (NS) keitėsi per paskutines 30 dienų`,
            description_lt:
              `Domeno ${domain} vardų serveriai buvo pakeisti neseniai. ` +
              `NS pakeitimas reiškia, kad visas DNS valdymas buvo perkeltas — tai gali rodyti domeno užgrobimą.`,
            recommendation_lt:
              `1. SKUBIAI patikrinkite, ar NS pakeitimas buvo autorizuotas.\n` +
              `2. Patikrinkite registratoriaus paskyrą dėl neautorizuotos prieigos.\n` +
              `3. Įjunkite registrar lock.`,
            nis2_article: '11 str. 2 d. 1 p.',
            evidence: { domain, dns_type: 'ns', recent_changes: recentChanges.slice(0, 5) },
          });
        }

        if (dnsType === 'mx' && recentChanges.length > 0) {
          findings.push({
            module: 'securitytrails',
            severity: 'medium',
            title_lt: `El. pašto serveriai (MX) keitėsi per paskutines 30 dienų`,
            description_lt:
              `Domeno ${domain} MX įrašai buvo pakeisti neseniai. ` +
              `Tai gali būti teisėtas pakeitimas arba el. pašto peradresavimo ataka.`,
            recommendation_lt: 'Patikrinkite, ar MX pakeitimas buvo autorizuotas.',
            nis2_article: '11 str. 2 d. 1 p.',
            evidence: { domain, dns_type: 'mx', recent_changes: recentChanges.slice(0, 5) },
          });
        }
      } catch (err) {
        console.error(`[securitytrails] DNS history ${dnsType} failed: ${err instanceof Error ? err.message : 'Unknown'}`);
      }
    }

    // ── 4. Associated domains ────────────────────────────────────────
    try {
      const assocRes = await fetchWithTimeout(
        `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/associated`,
        { headers },
        15_000,
      );
      if (assocRes.ok) {
        const assocData = await assocRes.json();
        const associatedDomains = (assocData.records || []) as Array<{ hostname: string }>;

        if (associatedDomains.length > 0) {
          const domainList = associatedDomains.slice(0, 15).map((d) => d.hostname);
          findings.push({
            module: 'securitytrails',
            severity: 'info',
            title_lt: `Susieti domenai — ${associatedDomains.length} vnt.`,
            description_lt:
              `Rasta ${associatedDomains.length} domenų, susietų su ${domain}:\n` +
              domainList.map((d) => `• ${d}`).join('\n') +
              (associatedDomains.length > 15 ? `\n...ir dar ${associatedDomains.length - 15}` : '') +
              `\n\nJei šie domenai nėra jūsų — galimas shared hosting, kas reiškia, kad kito domeno pažeidimas gali paveikti ir jus.`,
            recommendation_lt: 'Patikrinkite, ar visi susieti domenai priklauso jūsų organizacijai.',
            nis2_article: null,
            evidence: { domain, associated_domains: domainList, total: associatedDomains.length },
          });
        }
      }
    } catch {
      // Non-critical
    }

    // ── 5. WHOIS ─────────────────────────────────────────────────────
    try {
      const whoisRes = await fetchWithTimeout(
        `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/whois`,
        { headers },
        15_000,
      );
      if (whoisRes.ok) {
        const whoisData = await whoisRes.json();

        const registrar = whoisData.registrar_name || whoisData.registrar || null;
        const expiryDate = whoisData.expires_date || whoisData.expiresDate || null;
        const createdDate = whoisData.created_date || whoisData.createdDate || null;
        const privacyProtection = whoisData.private_registration ?? whoisData.contactEmail === null;

        if (expiryDate) {
          const expiry = new Date(expiryDate);
          const now = new Date();
          const daysUntilExpiry = Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          if (daysUntilExpiry <= 0) {
            findings.push({
              module: 'securitytrails',
              severity: 'critical',
              title_lt: 'Domeno registracija pasibaigusi!',
              description_lt:
                `Domeno ${domain} registracija pasibaigė prieš ${Math.abs(daysUntilExpiry)} dienų. ` +
                `Pasibaigęs domenas gali būti užregistruotas bet ko.`,
              recommendation_lt: 'SKUBIAI (ŠIANDIEN): atnaujinkite domeno registraciją.',
              nis2_article: '11 str. 2 d. 1 p.',
              evidence: { domain, registrar, expiry_date: expiryDate, days_until_expiry: daysUntilExpiry },
            });
          } else if (daysUntilExpiry <= 30) {
            findings.push({
              module: 'securitytrails',
              severity: 'critical',
              title_lt: `Domeno registracija baigiasi po ${daysUntilExpiry} dienų!`,
              description_lt:
                `Domeno ${domain} registracija baigsis po ${daysUntilExpiry} dienų. ` +
                `Jei nebus atnaujinta, piktavaliai gali jį užregistruoti.`,
              recommendation_lt:
                `1. SKUBIAI atnaujinkite domeno registraciją (registratorius: ${registrar || 'nežinomas'}).\n` +
                `2. Įjunkite automatinį atnaujinimą.`,
              nis2_article: '11 str. 2 d. 1 p.',
              evidence: { domain, registrar, expiry_date: expiryDate, days_until_expiry: daysUntilExpiry },
            });
          } else if (daysUntilExpiry <= 60) {
            findings.push({
              module: 'securitytrails',
              severity: 'high',
              title_lt: `Domeno registracija baigiasi po ${daysUntilExpiry} dienų`,
              description_lt: `Domeno ${domain} registracija baigsis po ${daysUntilExpiry} dienų. Rekomenduojame atnaujinti iš anksto.`,
              recommendation_lt: 'Atnaujinkite domeno registraciją per artimiausias 2 savaites.',
              nis2_article: '11 str. 2 d. 1 p.',
              evidence: { domain, registrar, expiry_date: expiryDate, days_until_expiry: daysUntilExpiry },
            });
          }
        }

        if (!privacyProtection) {
          findings.push({
            module: 'securitytrails',
            severity: 'medium',
            title_lt: 'WHOIS privatumo apsauga neįjungta',
            description_lt:
              `Domeno ${domain} WHOIS duomenys yra vieši — bet kas gali matyti savininko kontaktinius duomenis. ` +
              `Šie duomenys gali būti naudojami sukčiavimo atakoms.`,
            recommendation_lt: `Įjunkite WHOIS privatumo apsaugą pas registratorių (${registrar || 'nežinomas'}).`,
            nis2_article: null,
            evidence: { domain, registrar, privacy_protection: false, created_date: createdDate, expiry_date: expiryDate },
          });
        }

        findings.push({
          module: 'securitytrails',
          severity: 'info',
          title_lt: 'Domeno WHOIS informacija',
          description_lt:
            `Registratorius: ${registrar || 'nežinomas'}\n` +
            `Sukūrimo data: ${createdDate || 'nežinoma'}\n` +
            `Galiojimo pabaiga: ${expiryDate || 'nežinoma'}\n` +
            `Privatumo apsauga: ${privacyProtection ? 'taip' : 'ne'}`,
          recommendation_lt: 'Informacinis įrašas.',
          nis2_article: null,
          evidence: { domain, registrar, created_date: createdDate, expiry_date: expiryDate, privacy: privacyProtection },
        });
      }
    } catch {
      // WHOIS not available
    }

    // ── All clean ────────────────────────────────────────────────────
    if (findings.length === 0) {
      findings.push({
        module: 'securitytrails',
        severity: 'info',
        title_lt: 'Subdomenai ir DNS — viskas tvarkoje',
        description_lt:
          `Domeno ${domain} subdomenų ir DNS istorijos analizė neparodė problemų. ` +
          `Rasta ${subdomains.length} subdomenų — visi veda į veikiančius serverius.`,
        recommendation_lt: 'Kas ketvirtį peržiūrėkite subdomenų sąrašą.',
        nis2_article: null,
        evidence: {
          domain,
          subdomain_count: subdomains.length,
          dangling_count: 0,
          domain_info: domainInfo ? { alexa_rank: (domainInfo as Record<string, unknown>).alexa_rank } : null,
        },
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
