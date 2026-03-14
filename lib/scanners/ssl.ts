import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { formatLithuanianDate } from '@/lib/utils/date';

const MAX_POLLS = 10;
const POLL_INTERVAL_MS = 15_000;
const INITIAL_WAIT_MS = 15_000;

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * SSL Labs scanner — full-depth TLS assessment.
 * 1. Full analysis: GET /api/v3/analyze?host={domain}&all=done&ignoreMismatch=on
 *    Poll until status=READY, max 10 polls with 15s intervals
 * 2. Extract: grade, cert expiry, protocol versions, cipher suites,
 *    HSTS, vulnerabilities (Heartbleed, POODLE, DROWN, ROBOT),
 *    forward secrecy, certificate chain, HTTP redirect
 *
 * Severity: Critical if F/T grade or vuln, High if C/below or TLS1.0, Medium if B, Low if no HSTS
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
export async function scanSsl(domain: string): Promise<ScannerResult> {
  try {
    const host = encodeURIComponent(domain);
    const startUrl = `https://api.ssllabs.com/api/v3/analyze?host=${host}&all=done&startNew=on&ignoreMismatch=on`;
    const pollUrl = `https://api.ssllabs.com/api/v3/analyze?host=${host}&all=done&ignoreMismatch=on`;

    console.log(`[ssl] Starting new analysis: ${domain}`);

    // Step 1: Trigger new analysis
    let startRes = await fetchWithTimeout(startUrl, {}, 20_000);
    console.log(`[ssl] Start response: ${startRes.status}`);

    // Handle 529 (overloaded)
    if (startRes.status === 529) {
      console.log(`[ssl] Overloaded (529), waiting 30s and retrying...`);
      await sleep(30_000);
      startRes = await fetchWithTimeout(startUrl, {}, 20_000);
      if (startRes.status === 529) {
        return {
          module: 'ssl',
          success: true,
          findings: [{
            module: 'ssl', severity: 'info',
            title_lt: 'SSL Labs paslauga šiuo metu perkrauta',
            description_lt: `SSL Labs API šiuo metu yra perkrautas ir negali atlikti analizės domenui ${domain}. Tai yra laikina problema.`,
            recommendation_lt: 'Pakartokite skenavimą vėliau.',
            nis2_article: null,
            evidence: { domain, status: 529 },
          }],
        };
      }
    }

    if (startRes.status === 429) {
      return {
        module: 'ssl',
        success: true,
        findings: [{
          module: 'ssl', severity: 'info',
          title_lt: 'SSL Labs API limitas pasiektas',
          description_lt: `SSL Labs API užklausų limitas pasiektas skenojant domeną ${domain}.`,
          recommendation_lt: 'Pakartokite skenavimą vėliau.',
          nis2_article: null,
          evidence: { domain, status: 429 },
        }],
      };
    }

    if (!startRes.ok) {
      await startRes.text().catch(() => '');
      return { module: 'ssl', success: false, findings: [], error: `SSL Labs API returned: ${startRes.status}` };
    }

    let data: Record<string, unknown> = await startRes.json();

    // Step 2: Poll until READY
    if (data.status !== 'READY' && data.status !== 'ERROR') {
      console.log(`[ssl] Analysis started (${data.status}), waiting ${INITIAL_WAIT_MS / 1000}s...`);
      await sleep(INITIAL_WAIT_MS);

      for (let poll = 0; poll < MAX_POLLS; poll++) {
        const res = await fetchWithTimeout(pollUrl, {}, 20_000);
        console.log(`[ssl] Poll ${poll + 1}/${MAX_POLLS}: status ${res.status}`);

        if (res.status === 529) {
          await sleep(30_000);
          const retryRes = await fetchWithTimeout(pollUrl, {}, 20_000);
          if (!retryRes.ok) {
            return {
              module: 'ssl',
              success: true,
              findings: [{
                module: 'ssl', severity: 'info',
                title_lt: 'SSL Labs paslauga šiuo metu perkrauta',
                description_lt: `SSL Labs API perkrautas skenojant ${domain}.`,
                recommendation_lt: 'Pakartokite skenavimą vėliau.',
                nis2_article: null,
                evidence: { domain, status: retryRes.status },
              }],
            };
          }
          data = await retryRes.json();
        } else if (res.status === 429) {
          return {
            module: 'ssl',
            success: true,
            findings: [{
              module: 'ssl', severity: 'info',
              title_lt: 'SSL Labs API limitas pasiektas',
              description_lt: `SSL Labs API limitas pasiektas skenojant ${domain}.`,
              recommendation_lt: 'Pakartokite skenavimą vėliau.',
              nis2_article: null,
              evidence: { domain, status: 429 },
            }],
          };
        } else if (!res.ok) {
          await res.text().catch(() => '');
          return { module: 'ssl', success: false, findings: [], error: `SSL Labs API returned: ${res.status}` };
        } else {
          data = await res.json();
        }

        if (data.status === 'READY' || data.status === 'ERROR') break;

        if (poll < MAX_POLLS - 1) {
          console.log(`[ssl] In progress (${data.status}), polling in ${POLL_INTERVAL_MS / 1000}s...`);
          await sleep(POLL_INTERVAL_MS);
        }
      }
    }

    const findings: ScannerFinding[] = [];

    // Still not ready
    if (data.status === 'IN_PROGRESS' || data.status === 'DNS') {
      findings.push({
        module: 'ssl', severity: 'info',
        title_lt: 'SSL/TLS analizė dar nebaigta',
        description_lt: `SSL Labs analizė domenui ${domain} buvo pradėta, bet dar nebaigta. Rezultatai bus pasiekiami kitame skenavime.`,
        recommendation_lt: 'Pakartokite skenavimą po kelių minučių.',
        nis2_article: null,
        evidence: { domain, status: data.status },
      });
      return { module: 'ssl', success: true, findings };
    }

    if (data.status === 'ERROR') {
      findings.push({
        module: 'ssl', severity: 'high',
        title_lt: 'SSL/TLS sertifikatas nerastas arba nepasiekiamas',
        description_lt: `Domenas ${domain} neturi galiojančio SSL/TLS sertifikato arba serveris nepasiekiamas per HTTPS. Duomenys tarp naudotojo ir serverio perduodami nešifruotai — tai reiškia, kad bet kas tinkle gali perimti slaptažodžius, asmens duomenis ir kitą informaciją.`,
        recommendation_lt: 'Nedelsiant įdiekite SSL/TLS sertifikatą. Rekomenduojame nemokamą Let\'s Encrypt sertifikatą.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, status: data.status, statusMessage: data.statusMessage },
      });
      return { module: 'ssl', success: true, findings };
    }

    // ── Process each endpoint ────────────────────────────────────────
    const endpoints = (data.endpoints || []) as Array<Record<string, unknown>>;

    for (const endpoint of endpoints) {
      if (endpoint.statusMessage !== 'Ready') continue;

      const grade = (endpoint.grade as string) || 'Unknown';
      const ip = (endpoint.ipAddress as string) || '';
      const details = (endpoint.details || {}) as Record<string, unknown>;

      // ── Protocol versions ──────────────────────────────────────
      const protocols = (details.protocols || []) as Array<{ id: number; name: string; version: string }>;
      const protocolNames = protocols.map((p) => `${p.name} ${p.version}`);
      const hasTls10 = protocols.some((p) => p.name === 'TLS' && p.version === '1.0');
      const hasTls11 = protocols.some((p) => p.name === 'TLS' && p.version === '1.1');
      // TLS 1.2 presence tracked via protocolNames for evidence
      const hasTls13 = protocols.some((p) => p.name === 'TLS' && p.version === '1.3');
      const hasSsl30 = protocols.some((p) => p.name === 'SSL' && p.version === '3.0');

      // ── Cipher suites ──────────────────────────────────────────
      const suites = (details.suites || []) as Array<{ protocol: number; list: Array<{ name: string; cipherStrength: number }> }>;
      const weakCiphers: string[] = [];
      for (const suite of suites) {
        for (const cipher of (suite.list || [])) {
          if (cipher.cipherStrength < 128 || cipher.name.includes('RC4') || cipher.name.includes('DES') ||
              cipher.name.includes('NULL') || cipher.name.includes('EXPORT') || cipher.name.includes('anon')) {
            weakCiphers.push(`${cipher.name} (${cipher.cipherStrength} bit)`);
          }
        }
      }

      // ── Vulnerabilities ────────────────────────────────────────
      const heartbleed = !!details.heartbleed;
      const poodle = !!details.poodle;
      const drownVulnerable = !!details.drownVulnerable;
      const robotResult = details.robotResult as number | undefined;
      const isRobotVuln = robotResult !== undefined && robotResult !== 0 && robotResult !== 1; // 0=not vuln, 1=not vuln
      const freak = !!details.freak;
      const logjam = !!details.logjam;
      const openSslCcs = (details.openSslCcs as number) || 0;
      const isOpenSslCcsVuln = openSslCcs > 1;

      // ── HSTS ───────────────────────────────────────────────────
      const hstsPolicy = details.hstsPolicy as { status?: string; maxAge?: number; preload?: boolean } | undefined;
      const hasHsts = hstsPolicy?.status === 'present';
      const hstsMaxAge = hstsPolicy?.maxAge || 0;
      const hstsPreload = !!hstsPolicy?.preload;

      // ── Forward secrecy ────────────────────────────────────────
      const forwardSecrecy = (details.forwardSecrecy as number) || 0;
      // 1=at least one browser, 2=reference, 4=all suites
      const hasForwardSecrecy = forwardSecrecy >= 2;

      // ── HTTP redirect ──────────────────────────────────────────
      const httpForwarding = !!details.httpForwarding;

      // ── Certificate details ────────────────────────────────────
      const certChains = (details.certChains || []) as Array<{ certIds: number[]; issues: number }>;
      const hasChainIssues = certChains.some((c) => c.issues > 0);

      // ── Grade-based findings ───────────────────────────────────

      // Critical: F/T grade or known vulnerabilities
      if (grade === 'F' || grade === 'T' || grade === 'M') {
        findings.push({
          module: 'ssl',
          severity: 'critical',
          title_lt: `SSL/TLS vertinimas: ${grade} — kritinės problemos`,
          description_lt:
            `Serveris ${ip} (${domain}) gavo SSL Labs vertinimą „${grade}". ` +
            `${grade === 'T' ? 'Sertifikatas yra nepatikimas (self-signed arba pasibaigęs).' : ''}` +
            `${grade === 'F' ? 'Konfigūracija turi rimtų saugumo spragų.' : ''}` +
            `${grade === 'M' ? 'Sertifikato vardas nesutampa su domenu.' : ''}\n\n` +
            `Palaikomi protokolai: ${protocolNames.join(', ') || 'nenustatyta'}\n` +
            `${weakCiphers.length > 0 ? `Silpni šifrai: ${weakCiphers.slice(0, 5).join(', ')}\n` : ''}` +
            `Naudotojai matys saugumo įspėjimą naršyklėje ir daugelis negalės pasiekti svetainės.`,
          recommendation_lt:
            `1. SKUBIAI: patikrinkite ir atnaujinkite SSL/TLS sertifikatą.\n` +
            `2. Išjunkite senus protokolus (SSL 3.0, TLS 1.0, TLS 1.1).\n` +
            `3. Pašalinkite silpnus šifrus.\n` +
            `4. Naudokite tik TLS 1.2 ir TLS 1.3.\n` +
            `5. Rekomenduojame nemokamą Let's Encrypt sertifikatą su automatiniu atnaujinimu.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain, ip, grade,
            protocols: protocolNames,
            weak_ciphers: weakCiphers,
            has_chain_issues: hasChainIssues,
          },
        });
      }

      // Critical: Known vulnerabilities
      const vulnList: string[] = [];
      if (heartbleed) vulnList.push('Heartbleed (CVE-2014-0160) — leidžia nuskaityti serverio atmintį');
      if (poodle) vulnList.push('POODLE (CVE-2014-3566) — SSL 3.0 ataka');
      if (drownVulnerable) vulnList.push('DROWN (CVE-2016-0800) — SSLv2 ataka');
      if (isRobotVuln) vulnList.push('ROBOT — RSA dešifravimo ataka');
      if (freak) vulnList.push('FREAK (CVE-2015-0204) — EXPORT šifrų ataka');
      if (logjam) vulnList.push('Logjam (CVE-2015-4000) — silpnas Diffie-Hellman');
      if (isOpenSslCcsVuln) vulnList.push('OpenSSL CCS (CVE-2014-0224) — MitM ataka');

      if (vulnList.length > 0) {
        findings.push({
          module: 'ssl',
          severity: 'critical',
          title_lt: `SSL/TLS pažeidžiamumai — ${vulnList.length} žinomos atakos`,
          description_lt:
            `Serveris ${ip} (${domain}) yra pažeidžiamas šioms žinomoms atakoms:\n` +
            `${vulnList.map((v) => `• ${v}`).join('\n')}\n\n` +
            `Šios atakos leidžia piktavaliams perimti šifruotą ryšį, nuskaityti slaptažodžius ir asmens duomenis, ` +
            `arba apsimesti jūsų serveriu. Atakos įrankiai yra viešai prieinami.`,
          recommendation_lt:
            `1. SKUBIAI (per 24 val.): atnaujinkite OpenSSL ir kitas TLS bibliotekas.\n` +
            `2. Išjunkite SSL 2.0, SSL 3.0, TLS 1.0 ir TLS 1.1 protokolus.\n` +
            `3. Pašalinkite EXPORT ir RC4 šifrus.\n` +
            `4. Patikrinkite Diffie-Hellman parametrų dydį (min. 2048 bit).`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain, ip,
            heartbleed, poodle, drown: drownVulnerable,
            robot: isRobotVuln, freak, logjam,
            openssl_ccs: isOpenSslCcsVuln,
          },
        });
      }

      // High: Grade C/D/E or TLS 1.0 or cert expiring soon
      if ((grade === 'C' || grade === 'D' || grade === 'E') && vulnList.length === 0) {
        findings.push({
          module: 'ssl',
          severity: 'high',
          title_lt: `SSL/TLS vertinimas: ${grade} — reikia pataisymų`,
          description_lt:
            `Serveris ${ip} (${domain}) gavo vertinimą „${grade}". Konfigūracija turi saugumo trūkumų.\n\n` +
            `Palaikomi protokolai: ${protocolNames.join(', ')}\n` +
            `${hasTls10 ? '⚠ TLS 1.0 palaikomas — šis protokolas yra pasenęs ir pažeidžiamas.\n' : ''}` +
            `${hasTls11 ? '⚠ TLS 1.1 palaikomas — šis protokolas yra pasenęs.\n' : ''}` +
            `${hasSsl30 ? '⚠ SSL 3.0 palaikomas — šis protokolas yra kritiškai pažeidžiamas!\n' : ''}` +
            `${weakCiphers.length > 0 ? `Silpni šifrai: ${weakCiphers.slice(0, 3).join(', ')}\n` : ''}`,
          recommendation_lt:
            `1. Išjunkite TLS 1.0 ir TLS 1.1 — naudokite tik TLS 1.2 ir TLS 1.3.\n` +
            `2. Pašalinkite silpnus šifrus (RC4, DES, 3DES, EXPORT, NULL).\n` +
            `3. Terminas: per 14 dienų.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain, ip, grade,
            protocols: protocolNames,
            weak_ciphers: weakCiphers,
          },
        });
      } else if (hasTls10 && grade !== 'F' && grade !== 'T') {
        findings.push({
          module: 'ssl',
          severity: 'high',
          title_lt: 'Palaikomas pasenęs TLS 1.0 protokolas',
          description_lt:
            `Serveris ${ip} (${domain}) vis dar palaiko TLS 1.0 protokolą. ` +
            `Šis protokolas turi žinomų pažeidžiamumų (BEAST, POODLE) ir yra oficialiai nebepalaikomas nuo 2020 m.`,
          recommendation_lt: 'Išjunkite TLS 1.0 palaikymą serverio konfigūracijoje. Naudokite tik TLS 1.2 ir TLS 1.3.',
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: { domain, ip, protocols: protocolNames, tls10: true },
        });
      }

      // Medium: Grade B, TLS 1.1, no HSTS
      if (grade === 'B') {
        findings.push({
          module: 'ssl',
          severity: 'medium',
          title_lt: `SSL/TLS vertinimas: B — galimi patobulinimai`,
          description_lt:
            `Serveris ${ip} (${domain}) gavo vertinimą „B". Konfigūracija priimtina, bet galima pagerinti.\n\n` +
            `Palaikomi protokolai: ${protocolNames.join(', ')}\n` +
            `${hasTls11 ? '⚠ TLS 1.1 vis dar palaikomas (pasenęs nuo 2020 m.).\n' : ''}` +
            `${!hasForwardSecrecy ? '⚠ Forward secrecy nepalaikomas — seni šifruoti duomenys gali būti iššifruoti ateityje.\n' : ''}`,
          recommendation_lt:
            `1. Išjunkite TLS 1.1.\n` +
            `2. Prioritetizuokite ECDHE šifrus (forward secrecy).\n` +
            `3. Apsvarstykite HSTS antraštės pridėjimą.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: { domain, ip, grade, protocols: protocolNames, forward_secrecy: hasForwardSecrecy },
        });
      }

      if (!hasHsts) {
        findings.push({
          module: 'ssl',
          severity: 'medium',
          title_lt: 'HSTS antraštė neįjungta',
          description_lt:
            `Serveris ${ip} (${domain}) nenaudoja HSTS (HTTP Strict Transport Security) antraštės. ` +
            `Be HSTS, naudotojai gali būti nukreipti į nešifruotą HTTP versiją, kur piktavaliai gali perimti ryšį (MITM ataka).`,
          recommendation_lt:
            `1. Pridėkite HSTS antraštę: Strict-Transport-Security: max-age=31536000; includeSubDomains\n` +
            `2. Pradžioje naudokite trumpesnį max-age (pvz., 86400) testavimui.\n` +
            `3. Ateityje apsvarstykite HSTS preloading (Chrome preload sąrašas).`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: { domain, ip, hsts: false, hsts_preload: false },
        });
      } else if (!hstsPreload && hstsMaxAge < 31536000) {
        findings.push({
          module: 'ssl',
          severity: 'low',
          title_lt: 'HSTS konfigūracija galėtų būti stipresnė',
          description_lt:
            `HSTS antraštė yra, bet max-age yra ${hstsMaxAge}s (rekomenduojama ≥31536000, t.y. 1 metai). ` +
            `${!hstsPreload ? 'HSTS preloading neįjungtas.' : ''}`,
          recommendation_lt: 'Padidinkite max-age iki 31536000 ir apsvarstykite HSTS preloading.',
          nis2_article: null,
          evidence: { domain, ip, hsts_max_age: hstsMaxAge, hsts_preload: hstsPreload },
        });
      }

      // Low: No HTTP redirect
      if (!httpForwarding) {
        findings.push({
          module: 'ssl',
          severity: 'low',
          title_lt: 'HTTP→HTTPS peradresavimas neveikia',
          description_lt:
            `Serveris ${ip} (${domain}) neperadresuoja HTTP užklausų į HTTPS. ` +
            `Naudotojai, kurie atidaro svetainę be "https://", matys nešifruotą versiją.`,
          recommendation_lt: 'Nustatykite automatinį HTTP→HTTPS peradresavimą (301 redirect).',
          nis2_article: null,
          evidence: { domain, ip, http_forwarding: false },
        });
      }

      // Info: Good grade
      if ((grade === 'A' || grade === 'A+') && vulnList.length === 0) {
        findings.push({
          module: 'ssl',
          severity: 'info',
          title_lt: `SSL/TLS vertinimas: ${grade} — puiki konfigūracija`,
          description_lt:
            `Serveris ${ip} (${domain}) gavo aukščiausią SSL Labs vertinimą „${grade}". ` +
            `SSL/TLS konfigūracija atitinka geriausias praktikas.\n\n` +
            `Palaikomi protokolai: ${protocolNames.join(', ')}\n` +
            `${hasTls13 ? '✓ TLS 1.3 palaikomas (naujausias ir saugiausias).\n' : ''}` +
            `${hasForwardSecrecy ? '✓ Forward secrecy palaikomas.\n' : ''}` +
            `${hasHsts ? `✓ HSTS įjungtas (max-age: ${hstsMaxAge}s)${hstsPreload ? ', preloading aktyvus' : ''}.\n` : ''}` +
            `${httpForwarding ? '✓ HTTP→HTTPS peradresavimas veikia.\n' : ''}` +
            `${weakCiphers.length === 0 ? '✓ Silpnų šifrų nerasta.\n' : ''}`,
          recommendation_lt: 'Tęskite periodinį stebėjimą ir laiku atnaujinkite sertifikatą.',
          nis2_article: null,
          evidence: {
            domain, ip, grade,
            protocols: protocolNames,
            tls13: hasTls13,
            forward_secrecy: hasForwardSecrecy,
            hsts: hasHsts, hsts_max_age: hstsMaxAge, hsts_preload: hstsPreload,
            http_forwarding: httpForwarding,
            weak_ciphers: weakCiphers,
          },
        });
      }
    }

    // ── Certificate expiry ───────────────────────────────────────────
    const certs = (data.certs || []) as Array<{
      notAfter?: number;
      notBefore?: number;
      subject?: string;
      issuerSubject?: string;
      sigAlg?: string;
      keyAlg?: string;
      keySize?: number;
    }>;

    for (const cert of certs) {
      if (!cert.notAfter) continue;
      const expiryDate = new Date(cert.notAfter);
      const now = new Date();
      const daysUntilExpiry = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry < 0) {
        findings.push({
          module: 'ssl',
          severity: 'critical',
          title_lt: 'SSL/TLS sertifikatas pasibaigęs',
          description_lt:
            `Domeno ${domain} SSL/TLS sertifikatas pasibaigė prieš ${Math.abs(daysUntilExpiry)} dienų (${formatLithuanianDate(expiryDate)}). ` +
            `Naudotojai matys saugumo įspėjimą naršyklėje ir daugelis negalės pasiekti svetainės.\n\n` +
            `Sertifikato informacija: ${cert.subject || 'nežinomas'}, išdavė: ${cert.issuerSubject || 'nežinomas'}\n` +
            `Rakto algoritmas: ${cert.keyAlg || 'nežinomas'} ${cert.keySize ? `(${cert.keySize} bit)` : ''}`,
          recommendation_lt:
            `1. SKUBIAI (šiandien): atnaujinkite SSL/TLS sertifikatą.\n` +
            `2. Nustatykite automatinį sertifikatų atnaujinimą (pvz., certbot su Let's Encrypt).\n` +
            `3. Nustatykite priminimą 30 dienų prieš sertifikato galiojimo pabaigą.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain,
            expiry_date: expiryDate.toISOString(),
            days_until_expiry: daysUntilExpiry,
            subject: cert.subject,
            issuer: cert.issuerSubject,
            key_alg: cert.keyAlg,
            key_size: cert.keySize,
            sig_alg: cert.sigAlg,
          },
        });
      } else if (daysUntilExpiry <= 30) {
        findings.push({
          module: 'ssl',
          severity: 'high',
          title_lt: `SSL/TLS sertifikatas baigiasi po ${daysUntilExpiry} dienų`,
          description_lt:
            `Domeno ${domain} SSL/TLS sertifikatas baigsis ${formatLithuanianDate(expiryDate)} (po ${daysUntilExpiry} dienų). ` +
            `Jei sertifikatas nebus atnaujintas laiku, naudotojai negalės saugiai pasiekti svetainės.\n\n` +
            `Sertifikatas: ${cert.subject || domain}, išdavė: ${cert.issuerSubject || 'nežinomas'}`,
          recommendation_lt:
            `1. Nedelsiant pradėkite sertifikato atnaujinimo procesą.\n` +
            `2. Nustatykite automatinį atnaujinimą, kad tai nepasikartotų.`,
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: {
            domain,
            expiry_date: expiryDate.toISOString(),
            days_until_expiry: daysUntilExpiry,
            subject: cert.subject,
            issuer: cert.issuerSubject,
          },
        });
      } else if (daysUntilExpiry <= 60) {
        findings.push({
          module: 'ssl',
          severity: 'medium',
          title_lt: `SSL/TLS sertifikatas baigiasi po ${daysUntilExpiry} dienų`,
          description_lt:
            `Domeno ${domain} SSL/TLS sertifikatas baigsis ${formatLithuanianDate(expiryDate)}. ` +
            `Rekomenduojame atnaujinti iš anksto.`,
          recommendation_lt: 'Suplanuokite sertifikato atnaujinimą per artimiausias 2 savaites.',
          nis2_article: null,
          evidence: {
            domain,
            expiry_date: expiryDate.toISOString(),
            days_until_expiry: daysUntilExpiry,
          },
        });
      }

      // Weak key size
      if (cert.keySize && cert.keySize < 2048) {
        findings.push({
          module: 'ssl',
          severity: 'high',
          title_lt: `Silpnas sertifikato raktas — ${cert.keySize} bit`,
          description_lt:
            `Sertifikato rakto dydis yra tik ${cert.keySize} bit. Minimalus rekomenduojamas dydis yra 2048 bit RSA arba 256 bit ECC.`,
          recommendation_lt: 'Sugeneruokite naują sertifikatą su 2048 bit RSA arba 256 bit ECC raktu.',
          nis2_article: '11 str. 2 d. 5 p.',
          evidence: { domain, key_alg: cert.keyAlg, key_size: cert.keySize },
        });
      }
    }

    if (findings.length === 0) {
      findings.push({
        module: 'ssl',
        severity: 'info',
        title_lt: 'SSL/TLS skenavimas — problemų nerasta',
        description_lt: `Domeno ${domain} SSL/TLS konfigūracija atitinka standartus.`,
        recommendation_lt: 'Tęskite periodinį stebėjimą.',
        nis2_article: null,
        evidence: { domain, status: data.status },
      });
    }

    return { module: 'ssl', success: true, findings };
  } catch (err) {
    return {
      module: 'ssl',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
