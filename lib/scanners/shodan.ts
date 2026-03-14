import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

/**
 * Shodan scanner — full-depth host intelligence.
 * 1. DNS resolve: GET /dns/resolve?hostnames={domain}
 * 2. Host lookup: GET /shodan/host/{ip} — ports, banners, CVEs, OS
 * 3. Reverse DNS: GET /dns/reverse?ips={ip}
 * 4. Domain search: GET /shodan/host/search?query=hostname:{domain}
 * 5. CVE enrichment via cve.circl.lu
 *
 * Severity: Critical if CVSS ≥9.0, High if ≥7.0 or sensitive port, Medium if ≥4.0
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
export async function scanShodan(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.SHODAN_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'shodan', success: false, findings: [], error: 'SHODAN_API_KEY not configured' };
  }

  try {
    const findings: ScannerFinding[] = [];

    // ── Step 1: DNS resolve ──────────────────────────────────────────
    const dnsUrl = `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(domain)}&key=${apiKey}`;
    console.log(`[shodan] DNS resolve: ${domain}`);
    const dnsRes = await fetchWithTimeout(dnsUrl, {}, 15_000);
    console.log(`[shodan] DNS response: ${dnsRes.status}`);

    if (!dnsRes.ok) {
      await dnsRes.text().catch(() => '');
      return { module: 'shodan', success: false, findings: [], error: `DNS resolve failed: ${dnsRes.status}` };
    }

    const dnsData = await dnsRes.json();
    const primaryIp: string | null = dnsData[domain] ?? null;

    if (!primaryIp) {
      findings.push({
        module: 'shodan',
        severity: 'info',
        title_lt: 'Domenas nerastas Shodan duomenų bazėje',
        description_lt: `Domenas ${domain} neturi susieto IP adreso Shodan duomenų bazėje. Tai gali reikšti, kad domenas nėra aktyvus arba yra apsaugotas per CDN/proxy.`,
        recommendation_lt: 'Jokių papildomų veiksmų nereikia.',
        nis2_article: null,
        evidence: { domain, dns_result: dnsData },
      });
      return { module: 'shodan', success: true, findings };
    }

    // ── Step 2: Reverse DNS ──────────────────────────────────────────
    let reverseHostnames: string[] = [];
    try {
      const revRes = await fetchWithTimeout(
        `https://api.shodan.io/dns/reverse?ips=${encodeURIComponent(primaryIp)}&key=${apiKey}`,
        {},
        10_000,
      );
      if (revRes.ok) {
        const revData = await revRes.json();
        reverseHostnames = revData[primaryIp] || [];
      }
    } catch {
      // Non-critical
    }

    // ── Step 3: Domain search — find all IPs associated with domain ──
    const associatedIps = new Set<string>([primaryIp]);
    try {
      const searchRes = await fetchWithTimeout(
        `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=hostname:${encodeURIComponent(domain)}&minify=true`,
        {},
        15_000,
      );
      if (searchRes.ok) {
        const searchData = await searchRes.json();
        const matches = searchData.matches || [];
        for (const match of matches) {
          if (match.ip_str) associatedIps.add(match.ip_str);
        }
      }
    } catch {
      // Non-critical — continue with primary IP
    }

    if (associatedIps.size > 1) {
      findings.push({
        module: 'shodan',
        severity: 'info',
        title_lt: `Rasta ${associatedIps.size} IP adresų, susietų su domenu`,
        description_lt: `Domenas ${domain} susietas su ${associatedIps.size} skirtingais IP adresais: ${Array.from(associatedIps).join(', ')}. Kiekvienas IP adresas yra atskiras atakos taškas.`,
        recommendation_lt: 'Įsitikinkite, kad visi susieti IP adresai yra žinomi ir valdomi jūsų organizacijos.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, associated_ips: Array.from(associatedIps), reverse_hostnames: reverseHostnames },
      });
    }

    // ── Step 4: Host lookup for each IP ──────────────────────────────
    const allCves: Array<{ id: string; cvss: number | null; summary: string; exploited: boolean }> = [];
    const allPorts: Array<{ ip: string; port: number; service: string; product: string; version: string; banner: string }> = [];
    const allVulnIps: string[] = [];
    let osDetection: string | null = null;

    const ipsToCheck = Array.from(associatedIps).slice(0, 5); // Max 5 IPs to stay within timeout

    for (const ip of ipsToCheck) {
      console.log(`[shodan] Host lookup: ${ip}`);
      let hostRes: Response;
      try {
        hostRes = await fetchWithTimeout(
          `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`,
          {},
          15_000,
        );
      } catch {
        continue;
      }

      console.log(`[shodan] Host response for ${ip}: ${hostRes.status}`);

      if (hostRes.status === 404) continue;
      if (!hostRes.ok) {
        await hostRes.text().catch(() => '');
        continue;
      }

      const hostData = await hostRes.json();

      // OS detection
      if (!osDetection && hostData.os) {
        osDetection = hostData.os;
      }

      // Collect service banners from all ports
      const services = hostData.data || [];
      for (const svc of services) {
        allPorts.push({
          ip,
          port: svc.port || 0,
          service: svc._shodan?.module || svc.transport || '',
          product: svc.product || '',
          version: svc.version || '',
          banner: (svc.data || '').slice(0, 200),
        });
      }

      // Collect CVEs
      if (hostData.vulns && hostData.vulns.length > 0) {
        allVulnIps.push(ip);
        for (const cveId of hostData.vulns) {
          if (!allCves.find((c) => c.id === cveId)) {
            allCves.push({ id: cveId, cvss: null, summary: '', exploited: false });
          }
        }
      }
    }

    // ── Step 5: CVE enrichment via cve.circl.lu ──────────────────────
    const topCves = allCves.slice(0, 10);
    if (topCves.length > 0) {
      const cveChecks = await Promise.allSettled(
        topCves.map(async (cve) => {
          try {
            const cveRes = await fetchWithTimeout(
              `https://cve.circl.lu/api/cve/${cve.id}`,
              {},
              5_000,
            );
            if (cveRes.ok) {
              const data = await cveRes.json();
              cve.cvss = data.cvss ?? data.cvss_score ?? null;
              cve.summary = data.summary || data.description || '';
              cve.exploited = !!(
                data.exploit_published ||
                data.references?.some((r: string) => r.includes('exploit') || r.includes('metasploit'))
              );
            }
          } catch {
            // Ignore
          }
        }),
      );
      // Wait for all CVE lookups
      void cveChecks;
    }

    // Sort by CVSS desc
    allCves.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

    // ── Generate findings ────────────────────────────────────────────

    // CVE findings — split by severity
    const criticalCves = allCves.filter((c) => c.cvss !== null && c.cvss >= 9.0);
    const highCves = allCves.filter((c) => c.cvss !== null && c.cvss >= 7.0 && c.cvss < 9.0);
    const mediumCves = allCves.filter((c) => c.cvss !== null && c.cvss >= 4.0 && c.cvss < 7.0);
    const unknownCves = allCves.filter((c) => c.cvss === null);

    if (criticalCves.length > 0) {
      const cveList = criticalCves.map((c) => {
        const exploitStr = c.exploited ? ' — ŽINOMAS IŠNAUDOJIMAS' : '';
        const summaryStr = c.summary ? `: ${c.summary.slice(0, 150)}` : '';
        return `• ${c.id} (CVSS: ${c.cvss})${exploitStr}${summaryStr}`;
      }).join('\n');

      findings.push({
        module: 'shodan',
        severity: 'critical',
        title_lt: `Kritinės pažeidžiamumo vietos (CVSS ≥9.0) — ${criticalCves.length} vnt.`,
        description_lt:
          `Jūsų infrastruktūroje aptiktos kritinės programinės įrangos pažeidžiamumo vietos su aukščiausiais pavojingumo balais (CVSS ≥9.0). ` +
          `Šios spragos leidžia piktavaliams visiškai perimti serverio kontrolę, pavogti visus duomenis arba sustabdyti veiklą.\n\n` +
          `Kritinės pažeidžiamumo vietos:\n${cveList}\n\n` +
          `Paveikti IP adresai: ${allVulnIps.join(', ')}\n` +
          `${osDetection ? `Aptikta operacinė sistema: ${osDetection}\n` : ''}` +
          `Verslo poveikis: pagal KSĮ 11 str. 2 d. 5 p. organizacija privalo užtikrinti tinklų saugumą. Baudos iki 10 mln. EUR arba 2% metinės apyvartos.`,
        recommendation_lt:
          `1. SKUBIAI (per 24 val.): perduokite šį CVE sąrašą IT administratoriui.\n` +
          `2. Per 7 dienas: atnaujinkite visą programinę įrangą su kritiniais CVE.\n` +
          `3. Jei atnaujinti neįmanoma — nedelsiant apribokite prieigą per užkardą.\n` +
          `4. Pirmenybę teikite CVE su pažymėtu "ŽINOMAS IŠNAUDOJIMAS" — tai reiškia, kad atakos įrankiai jau egzistuoja.\n` +
          `5. Po atnaujinimo pakartokite skenavimą.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain,
          affected_ips: allVulnIps,
          critical_cves: criticalCves,
          os_detection: osDetection,
          total_cve_count: allCves.length,
        },
      });
    }

    if (highCves.length > 0) {
      const cveList = highCves.slice(0, 8).map((c) => {
        const exploitStr = c.exploited ? ' — ŽINOMAS IŠNAUDOJIMAS' : '';
        return `• ${c.id} (CVSS: ${c.cvss})${exploitStr}`;
      }).join('\n');

      findings.push({
        module: 'shodan',
        severity: 'high',
        title_lt: `Aukšto pavojingumo pažeidžiamumo vietos (CVSS 7.0–8.9) — ${highCves.length} vnt.`,
        description_lt:
          `Rastos aukšto pavojingumo programinės įrangos spragos:\n${cveList}\n\n` +
          `Šios spragos gali leisti piktavaliams gauti dalinę prieigą prie serverio, pavogti tam tikrus duomenis arba sutrikdyti paslaugų veikimą.`,
        recommendation_lt:
          `1. Per 14 dienų: paruoškite atnaujinimo planą visoms aukšto pavojingumo CVE.\n` +
          `2. Per 30 dienų: įdiekite visus atnaujinimus.\n` +
          `3. Stebėkite serverio veiklą dėl neautorizuotos prieigos požymių.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain,
          affected_ips: allVulnIps,
          high_cves: highCves,
        },
      });
    }

    if (mediumCves.length > 0) {
      findings.push({
        module: 'shodan',
        severity: 'medium',
        title_lt: `Vidutinio pavojingumo pažeidžiamumo vietos (CVSS 4.0–6.9) — ${mediumCves.length} vnt.`,
        description_lt:
          `Rastos ${mediumCves.length} vidutinio pavojingumo programinės įrangos spragos. ` +
          `Pavienės jos nekelia tiesioginio pavojaus, bet kartu su kitomis problemomis gali būti panaudotos atakai.`,
        recommendation_lt:
          `1. Įtraukite į reguliarų atnaujinimo ciklą (per 60 dienų).\n` +
          `2. Stebėkite, ar kuris nors iš šių CVE neįgauna žinomo išnaudojimo.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain,
          medium_cves: mediumCves.map((c) => ({ id: c.id, cvss: c.cvss })),
        },
      });
    }

    if (unknownCves.length > 0 && criticalCves.length === 0 && highCves.length === 0) {
      findings.push({
        module: 'shodan',
        severity: 'high',
        title_lt: `Rastos pažeidžiamumo vietos be CVSS balo — ${unknownCves.length} vnt.`,
        description_lt:
          `Aptikta ${unknownCves.length} pažeidžiamumo vietų, kurių pavojingumas negalėjo būti įvertintas automatiškai: ` +
          `${unknownCves.slice(0, 5).map((c) => c.id).join(', ')}${unknownCves.length > 5 ? ` ir dar ${unknownCves.length - 5}` : ''}. ` +
          `Rekomenduojama patikrinti kiekvieną rankiniu būdu.`,
        recommendation_lt:
          `1. IT administratorius turėtų patikrinti kiekvieną CVE ID rankiniu būdu.\n` +
          `2. Atnaujinkite programinę įrangą iki naujausių versijų.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, unknown_cves: unknownCves.map((c) => c.id) },
      });
    }

    // ── Open ports analysis ──────────────────────────────────────────
    const sensitivePorts: Record<number, string> = {
      21: 'FTP (failų perdavimas)', 22: 'SSH (nuotolinė prieiga)', 23: 'Telnet (nešifruotas)',
      25: 'SMTP (el. paštas)', 135: 'RPC (Windows)', 139: 'NetBIOS (Windows)',
      445: 'SMB (failų dalinimasis)', 1433: 'MS SQL duomenų bazė', 1521: 'Oracle duomenų bazė',
      3306: 'MySQL duomenų bazė', 3389: 'RDP (nuotolinis darbalaukis)', 5432: 'PostgreSQL duomenų bazė',
      5900: 'VNC (nuotolinis ekranas)', 6379: 'Redis (talpykla)', 27017: 'MongoDB duomenų bazė',
      9200: 'Elasticsearch', 11211: 'Memcached', 8080: 'HTTP proxy/alternatyvus',
    };

    const exposedSensitive: Array<{ ip: string; port: number; service: string; product: string; version: string }> = [];
    const allPortsList: Array<{ ip: string; port: number; service: string }> = [];

    for (const p of allPorts) {
      allPortsList.push({ ip: p.ip, port: p.port, service: p.service });
      if (sensitivePorts[p.port]) {
        exposedSensitive.push({ ip: p.ip, port: p.port, service: p.service, product: p.product, version: p.version });
      }
    }

    if (exposedSensitive.length > 0) {
      const portList = exposedSensitive.map((p) => {
        const desc = sensitivePorts[p.port] || 'nežinomas';
        const versionStr = p.product ? ` — ${p.product}${p.version ? ' ' + p.version : ''}` : '';
        return `• ${p.ip}:${p.port} (${desc})${versionStr}`;
      }).join('\n');

      findings.push({
        module: 'shodan',
        severity: 'high',
        title_lt: `Eksponuotos jautrios paslaugos — ${exposedSensitive.length} prievadai`,
        description_lt:
          `Jūsų infrastruktūroje rasti atviri prievadai, kurie leidžia bet kam internete bandyti prisijungti prie jautrių paslaugų:\n` +
          `${portList}\n\n` +
          `Tai kaip palikti atrakintus durų užraktus — automatizuoti įrankiai nuolat skenuoja internetą ieškodami tokių atvirų prievadų ` +
          `ir bando prisijungti naudodami žinomus slaptažodžius ar pažeidžiamumus.\n\n` +
          `${reverseHostnames.length > 0 ? `Į šį IP adresą taip pat rodo kiti domenai: ${reverseHostnames.slice(0, 5).join(', ')}. ` : ''}` +
          `Verslo poveikis: per šiuos prievadus piktavaliai gali perimti serverį, pasiekti duomenų bazes, šifruoti duomenis (ransomware).`,
        recommendation_lt:
          `1. Nedelsdami kreipkitės į IT administratorių ir paprašykite užblokuoti prievadus per užkardą.\n` +
          `2. Jei paslaugos reikalingos nuotoliniam darbui (SSH, RDP) — nustatykite VPN prieigą.\n` +
          `3. Pakeiskite visus numatytuosius slaptažodžius.\n` +
          `4. Duomenų bazių prievadai (MySQL, PostgreSQL, MongoDB, Redis) NIEKADA neturėtų būti prieinami iš interneto.\n` +
          `5. Terminas: per 7 dienas užblokuoti nereikalingus prievadus, per 14 dienų nustatyti VPN.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain,
          exposed_sensitive: exposedSensitive,
          reverse_hostnames: reverseHostnames,
          os_detection: osDetection,
        },
      });
    }

    // ── Outdated software detection ──────────────────────────────────
    const outdatedSoftware: Array<{ ip: string; port: number; product: string; version: string }> = [];
    for (const p of allPorts) {
      if (!p.product || !p.version) continue;
      const prod = p.product.toLowerCase();
      const ver = p.version;

      // Apache 1.x
      if (prod.includes('apache') && ver.match(/^1\./)) {
        outdatedSoftware.push(p);
      }
      // OpenSSH < 8.0
      else if (prod.includes('openssh') && ver.match(/^[1-7]\./)) {
        outdatedSoftware.push(p);
      }
      // nginx < 1.18
      else if (prod.includes('nginx') && ver.match(/^(0\.|1\.(0|1[0-7])\.)/)) {
        outdatedSoftware.push(p);
      }
      // PHP < 8.0
      else if (prod.includes('php') && ver.match(/^[1-7]\./)) {
        outdatedSoftware.push(p);
      }
      // ProFTPD, vsftpd old versions
      else if ((prod.includes('proftpd') || prod.includes('vsftpd')) && ver.match(/^[0-2]\./)) {
        outdatedSoftware.push(p);
      }
      // IIS < 10
      else if (prod.includes('iis') && ver.match(/^[1-9]\./) && !ver.match(/^1[0-9]/)) {
        outdatedSoftware.push(p);
      }
    }

    if (outdatedSoftware.length > 0) {
      const swList = outdatedSoftware.map((s) =>
        `• ${s.ip}:${s.port} — ${s.product} ${s.version}`
      ).join('\n');

      findings.push({
        module: 'shodan',
        severity: 'high',
        title_lt: `Pasenusi programinė įranga — ${outdatedSoftware.length} atvejų`,
        description_lt:
          `Aptikta pasenusi programinė įranga, kuri nebegauna saugumo atnaujinimų:\n${swList}\n\n` +
          `Pasenusi programinė įranga dažnai turi žinomų pažeidžiamumų, kurie nėra taisomi, ` +
          `todėl serveris tampa lengvu taikiniu.`,
        recommendation_lt:
          `1. Atnaujinkite kiekvieną nurodytą programą iki naujausios palaikomos versijos.\n` +
          `2. Jei programa nebeplėtojama — pereikite prie alternatyvos.\n` +
          `3. Terminas: per 30 dienų.`,
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, outdated_software: outdatedSoftware },
      });
    }

    // ── All clean ────────────────────────────────────────────────────
    if (findings.length === 0) {
      findings.push({
        module: 'shodan',
        severity: 'info',
        title_lt: 'Shodan skenavimas — problemų nerasta',
        description_lt:
          `Domeno ${domain} (IP: ${primaryIp}) Shodan analizė neparodė kritinių rizikų. ` +
          `Jokių atvirų jautrių prievadų, žinomų pažeidžiamumų ar pasenusios programinės įrangos neaptikta.\n\n` +
          `${osDetection ? `Aptikta operacinė sistema: ${osDetection}. ` : ''}` +
          `Atviri prievadai: ${allPortsList.length > 0 ? allPortsList.map((p) => `${p.port}`).join(', ') : 'nerasta'}.`,
        recommendation_lt: 'Tęskite periodinį stebėjimą.',
        nis2_article: null,
        evidence: {
          domain,
          ip: primaryIp,
          associated_ips: Array.from(associatedIps),
          ports: allPortsList,
          os: osDetection,
          reverse_hostnames: reverseHostnames,
        },
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
