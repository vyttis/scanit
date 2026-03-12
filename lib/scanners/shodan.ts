import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

const SHODAN_API_KEY = process.env.SHODAN_API_KEY;

/**
 * Shodan scanner — checks open ports, exposed services, CVEs.
 * Severity: Critical if known CVE, High if sensitive service exposed.
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
export async function scanShodan(domain: string): Promise<ScannerResult> {
  if (!SHODAN_API_KEY) {
    return { module: 'shodan', success: false, findings: [], error: 'SHODAN_API_KEY not configured' };
  }

  try {
    // Resolve domain to IP first via Shodan DNS
    const dnsRes = await fetchWithTimeout(
      `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(domain)}&key=${SHODAN_API_KEY}`,
    );

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
    const hostRes = await fetchWithTimeout(
      `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`,
    );

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

    // Check for CVEs (vulns)
    if (hostData.vulns && hostData.vulns.length > 0) {
      findings.push({
        module: 'shodan',
        severity: 'critical',
        title_lt: `Rastos žinomos pažeidžiamumo vietos (CVE) — ${hostData.vulns.length} vnt.`,
        description_lt: `IP adrese ${ip} (${domain}) aptiktos žinomos pažeidžiamumo vietos: ${hostData.vulns.slice(0, 10).join(', ')}${hostData.vulns.length > 10 ? ` ir dar ${hostData.vulns.length - 10}` : ''}. Šios pažeidžiamumo vietos gali būti išnaudojamos piktavalių atakoms vykdyti.`,
        recommendation_lt: 'Skubiai atnaujinkite programinę įrangą ir operacinę sistemą. Patikrinkite, ar visi aptikti CVE yra pataisyti naujausiais saugumo atnaujinimais.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { ip, vulns: hostData.vulns, domain },
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
        description_lt: `IP adrese ${ip} (${domain}) rasti atidaryti jautrūs prievadai: ${portList}. Šios paslaugos neturėtų būti tiesiogiai pasiekiamos iš interneto, nes tai padidina atakos paviršių ir galimybę piktavaliams pasiekti jūsų sistemas.`,
        recommendation_lt: 'Uždarykite nereikalingus prievadus naudodami užkardą (firewall). Jei paslaugos būtinos — apribokite prieigą tik iš konkrečių IP adresų arba naudokite VPN.',
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
