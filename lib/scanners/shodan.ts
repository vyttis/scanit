import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

/**
 * Shodan scanner — checks open ports, exposed services, CVEs.
 * Severity: Critical if known CVE, High if sensitive service exposed.
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 *
 * @param options.ipRanges - Additional IP ranges to scan (professional plan)
 */
export async function scanShodan(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.SHODAN_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'shodan', success: false, findings: [], error: 'SHODAN_API_KEY not configured' };
  }

  try {
    // Resolve domain to IP first via Shodan DNS
    const dnsUrl = `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(domain)}&key=${apiKey}`;
    console.log(`[shodan] DNS resolve: ${domain}`);
    const dnsRes = await fetchWithTimeout(dnsUrl, {}, 15_000);

    console.log(`[shodan] DNS response: ${dnsRes.status}`);
    if (!dnsRes.ok) {
      return { module: 'shodan', success: false, findings: [], error: `DNS resolve failed: ${dnsRes.status}` };
    }

    const dnsData = await dnsRes.json();
    const ip = dnsData[domain];

    if (!ip) {
      return {
        module: 'shodan',
        success: true,
        findings: [{
          module: 'shodan',
          severity: 'info',
          title_lt: 'Domenas nerastas Shodan duomenų bazėje',
          description_lt: `Domenas ${domain} neturi susieto IP adreso Shodan duomenų bazėje. Tai gali reikšti, kad domenas nėra aktyvus arba yra apsaugotas per CDN/proxy.`,
          recommendation_lt: 'Jokių papildomų veiksmų nereikia.',
          nis2_article: null,
          evidence: { domain, dns_result: dnsData },
        }],
      };
    }

    // Get host info
    console.log(`[shodan] Host lookup: ${ip}`);
    const hostRes = await fetchWithTimeout(
      `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`,
      {},
      15_000,
    );
    console.log(`[shodan] Host response: ${hostRes.status}`);

    if (hostRes.status === 404) {
      return {
        module: 'shodan',
        success: true,
        findings: [{
          module: 'shodan',
          severity: 'info',
          title_lt: 'IP adresas nerastas Shodan duomenų bazėje',
          description_lt: `IP adresas ${ip} (${domain}) nerastas Shodan duomenų bazėje. Tai reiškia, kad Shodan dar neskenavo šio adreso arba jis neturi atvirų prievadų.`,
          recommendation_lt: 'Jokių papildomų veiksmų nereikia.',
          nis2_article: null,
          evidence: { domain, ip },
        }],
      };
    }

    if (!hostRes.ok) {
      return { module: 'shodan', success: false, findings: [], error: `Host lookup failed: ${hostRes.status}` };
    }

    const hostData = await hostRes.json();
    const findings: ScannerFinding[] = [];

    // Check for CVEs (vulns) — enrich top CVEs with CVSS data
    if (hostData.vulns && hostData.vulns.length > 0) {
      // Fetch details for top 5 CVEs from cve.circl.lu (free, no auth)
      const topCves = hostData.vulns.slice(0, 5);
      const cveDetails: Array<{
        id: string;
        cvss: number | null;
        summary: string;
        exploited: boolean;
      }> = [];

      const cveChecks = await Promise.allSettled(
        topCves.map(async (cveId: string) => {
          try {
            const cveRes = await fetchWithTimeout(
              `https://cve.circl.lu/api/cve/${cveId}`,
              {},
              5_000,
            );
            if (cveRes.ok) {
              const cveData = await cveRes.json();
              return {
                id: cveId,
                cvss: cveData.cvss ?? cveData.cvss_score ?? null,
                summary: cveData.summary || cveData.description || '',
                exploited: !!(cveData.exploit_published || cveData.references?.some((r: string) =>
                  r.includes('exploit') || r.includes('metasploit'))),
              };
            }
          } catch {
            // Ignore individual CVE lookup failures
          }
          return { id: cveId, cvss: null, summary: '', exploited: false };
        }),
      );

      for (const result of cveChecks) {
        if (result.status === 'fulfilled') {
          cveDetails.push(result.value);
        }
      }

      // Sort by CVSS score (highest first)
      cveDetails.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

      // Build detailed CVE list for description
      const cveList = cveDetails.map((cve) => {
        const cvssLabel = cve.cvss !== null
          ? (cve.cvss >= 9 ? 'Kritinis' : cve.cvss >= 7 ? 'Aukštas' : cve.cvss >= 4 ? 'Vidutinis' : 'Žemas')
          : 'Nežinomas';
        const cvssStr = cve.cvss !== null ? ` (CVSS: ${cve.cvss}, ${cvssLabel})` : '';
        const exploitStr = cve.exploited ? ' — ŽINOMAS IŠNAUDOJIMAS' : '';
        const summaryStr = cve.summary ? `: ${cve.summary.slice(0, 150)}` : '';
        return `${cve.id}${cvssStr}${exploitStr}${summaryStr}`;
      }).join('\n');

      const remainingCount = hostData.vulns.length - topCves.length;
      const remainingStr = remainingCount > 0 ? `\n...ir dar ${remainingCount} pažeidžiamumų.` : '';

      findings.push({
        module: 'shodan',
        severity: 'critical',
        title_lt: `Rastos žinomos pažeidžiamumo vietos (CVE) — ${hostData.vulns.length} vnt.`,
        description_lt:
          `Jūsų serverio IP adrese ${ip} (${domain}) aptiktos žinomos programinės įrangos pažeidžiamumo vietos. ` +
          `Tai reiškia, kad jūsų serveryje veikianti programinė įranga turi saugumo spragų, apie kurias žino ir piktavaliai. ` +
          `Jei šios spragos nebus uždarytos — piktavaliai gali jas panaudoti norėdami perimti serverio kontrolę, pavogti duomenis arba sustabdyti paslaugų veikimą.\n\n` +
          `Svarbiausios pažeidžiamumo vietos:\n${cveList}${remainingStr}\n\n` +
          `Verslo poveikis: pagal KSĮ 11 str. 2 d. 5 p. organizacija privalo užtikrinti tinklų ir informacinių sistemų saugumą. ` +
          `Neištaisytos pažeidžiamumo vietos gali būti traktuojamos kaip KSĮ pažeidimas, už kurį gresia baudos iki 10 mln. EUR arba 2% metinės apyvartos.`,
        recommendation_lt:
          `1. Perduokite šį CVE sąrašą IT administratoriui ir paprašykite per 7 dienas pateikti atnaujinimo planą.\n` +
          `2. Pirmiausia taisykite CVE su aukščiausiu CVSS balu ir žinomu išnaudojimu (pažymėti "ŽINOMAS IŠNAUDOJIMAS").\n` +
          `3. Atnaujinkite visą serverio programinę įrangą iki naujausių versijų per 30 dienų.\n` +
          `4. Jei atnaujinti neįmanoma — apribokite prieigą prie pažeidžiamų paslaugų per užkardą (firewall).\n` +
          `5. Po atnaujinimo pakartokite skenavimą, kad patvirtintumėte, jog pažeidžiamumai pašalinti.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          ip,
          domain,
          vulns: hostData.vulns,
          cve_details: cveDetails,
          total_cve_count: hostData.vulns.length,
        },
      });
    }

    // Check open ports
    const ports: number[] = hostData.ports || [];
    const sensitivePorts = [21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017];
    const exposedSensitive = ports.filter((p: number) => sensitivePorts.includes(p));

    if (exposedSensitive.length > 0) {
      const portDescriptions: Record<number, string> = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 135: 'RPC',
        139: 'NetBIOS', 445: 'SMB', 1433: 'MS SQL', 1521: 'Oracle DB',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 27017: 'MongoDB',
      };
      const portList = exposedSensitive.map((p: number) => `${p} (${portDescriptions[p] || 'nežinomas'})`).join(', ');

      findings.push({
        module: 'shodan',
        severity: 'high',
        title_lt: `Eksponuotos jautrios paslaugos — ${exposedSensitive.length} prievadai`,
        description_lt:
          `Jūsų serveryje ${ip} (${domain}) rasti atviri prievadai, kurie leidžia bet kam internete bandyti prisijungti prie jautrių paslaugų: ${portList}.\n\n` +
          `Tai kaip palikti atrakintus durų užraktus — net jei turite slaptažodį, pats faktas, kad durys matomos visiems, kviečia bandyti jas atidaryti. ` +
          `Automatizuoti įrankiai nuolat skenuoja internetą ieškodami tokių atvirų prievadų ir bando prisijungti naudodami žinomus slaptažodžius ar pažeidžiamumus.\n\n` +
          `Verslo poveikis: per šiuos prievadus piktavaliai gali perimti jūsų serverį, pasiekti duomenų bazes, ` +
          `šifruoti duomenis (ransomware) arba naudoti serverį atakoms prieš kitas organizacijas.`,
        recommendation_lt:
          `1. Nedelsdami kreipkitės į IT administratorių ir paprašykite užblokuoti šiuos prievadus per užkardą (firewall): ${portList}.\n` +
          `2. Jei paslaugos reikalingos nuotoliniam darbui (pvz., SSH, RDP) — nustatykite VPN prieigą ir leiskite jungtis tik per VPN.\n` +
          `3. Pakeiskite visus numatytuosius slaptažodžius šiose paslaugose.\n` +
          `4. Terminas: per 7 dienas užblokuoti nereikalingus prievadus, per 14 dienų — nustatyti VPN.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { ip, exposed_ports: exposedSensitive, all_ports: ports, domain },
      });
    }

    // General open ports info
    if (ports.length > 0 && findings.length === 0) {
      findings.push({
        module: 'shodan',
        severity: 'info',
        title_lt: `Rasti ${ports.length} atviri prievadai`,
        description_lt: `IP adrese ${ip} (${domain}) rasti ${ports.length} atviri prievadai: ${ports.join(', ')}. Kritinių paslaugų neaptikta.`,
        recommendation_lt: 'Periodiškai peržiūrėkite atvirų prievadų sąrašą ir uždarykite nereikalingus.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { ip, ports, domain },
      });
    }

    // Check each service banner for interesting info
    const data = hostData.data || [];
    for (const service of data) {
      // Check for outdated software in banners
      if (service.product && service.version) {
        const banner = `${service.product} ${service.version}`;
        // Check for known end-of-life or very old versions
        if (service.product.toLowerCase().includes('apache') && service.version.match(/^1\./)) {
          findings.push({
            module: 'shodan',
            severity: 'high',
            title_lt: `Pasenusi programinė įranga: ${banner}`,
            description_lt: `Prievade ${service.port} aptikta pasenusi programinė įranga: ${banner}. Senos versijos dažnai turi žinomų pažeidžiamumų, kurie nėra taisomi.`,
            recommendation_lt: `Atnaujinkite ${service.product} iki naujausios palaikomos versijos.`,
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { ip, port: service.port, product: service.product, version: service.version, domain },
          });
        }
      }
    }

    if (findings.length === 0) {
      findings.push({
        module: 'shodan',
        severity: 'info',
        title_lt: 'Shodan skenavimas — problemų nerasta',
        description_lt: `Domeno ${domain} (IP: ${ip}) Shodan analizė neparodė kritinių ar aukštų rizikų. Jokių atvirų jautrių prievadų ar žinomų pažeidžiamumų neaptikta.`,
        recommendation_lt: 'Tęskite periodinį stebėjimą.',
        nis2_article: null,
        evidence: { ip, ports, domain },
      });
    }

    return { module: 'shodan', success: true, findings };
  } catch (err) {
    return {
      module: 'shodan',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
