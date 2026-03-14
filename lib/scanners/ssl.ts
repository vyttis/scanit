import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { formatLithuanianDate } from '@/lib/utils/date';

const MAX_POLLS = 4;
const POLL_INTERVAL_MS = 10_000;
const INITIAL_WAIT_MS = 15_000;

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * SSL Labs scanner — checks certificate validity, expiry, cipher strength.
 * Severity: Critical if expired, High if expiring <30 days or weak cipher.
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 *
 * @param options.subdomains - Additional subdomains to check SSL on (professional plan)
 */
export async function scanSsl(domain: string): Promise<ScannerResult> {
  try {
    const host = encodeURIComponent(domain);
    const startUrl = `https://api.ssllabs.com/api/v3/analyze?host=${host}&all=done&startNew=on`;
    const pollUrl = `https://api.ssllabs.com/api/v3/analyze?host=${host}&all=done`;

    console.log(`[ssl] Starting new analysis: ${startUrl}`);

    // Step 1: Trigger new analysis with startNew=on
    let startRes = await fetchWithTimeout(startUrl, {}, 20_000);
    console.log(`[ssl] Start response: ${startRes.status}`);

    // Handle 529 on initial request
    if (startRes.status === 529) {
      console.log(`[ssl] Overloaded (529) on start, waiting 30s and retrying...`);
      await sleep(30_000);
      startRes = await fetchWithTimeout(startUrl, {}, 20_000);
      console.log(`[ssl] Retry start response: ${startRes.status}`);
      if (startRes.status === 529) {
        return {
          module: 'ssl',
          success: true,
          findings: [{
            module: 'ssl',
            severity: 'info',
            title_lt: 'SSL Labs paslauga šiuo metu perkrauta',
            description_lt: `SSL Labs API šiuo metu yra perkrautas ir negali atlikti analizės domenui ${domain}. Tai yra laikina problema iš SSL Labs pusės.`,
            recommendation_lt: 'Pakartokite skenavimą vėliau, kad gautumėte SSL/TLS rezultatus.',
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
          module: 'ssl',
          severity: 'info',
          title_lt: 'SSL Labs API limitas pasiektas',
          description_lt: `SSL Labs API užklausų limitas pasiektas skenojant domeną ${domain}. Tai yra laikina problema.`,
          recommendation_lt: 'Pakartokite skenavimą vėliau.',
          nis2_article: null,
          evidence: { domain, status: 429 },
        }],
      };
    }

    if (!startRes.ok) {
      return { module: 'ssl', success: false, findings: [], error: `SSL Labs API returned: ${startRes.status}` };
    }

    let data: Record<string, unknown> = await startRes.json();

    // Check if already ready (cached result)
    if (data.status === 'READY' || data.status === 'ERROR') {
      console.log(`[ssl] Immediate result: ${data.status}`);
    } else {
      // Step 2: Wait 15s before first poll
      console.log(`[ssl] Analysis started (${data.status}), waiting ${INITIAL_WAIT_MS / 1000}s before polling...`);
      await sleep(INITIAL_WAIT_MS);

      // Step 3: Poll without startNew
      for (let poll = 0; poll < MAX_POLLS; poll++) {
        const res = await fetchWithTimeout(pollUrl, {}, 20_000);
        console.log(`[ssl] Poll ${poll + 1}/${MAX_POLLS}: status ${res.status}`);

        if (res.status === 529) {
          console.log(`[ssl] Overloaded (529) on poll, waiting 30s and retrying...`);
          await sleep(30_000);
          const retryRes = await fetchWithTimeout(pollUrl, {}, 20_000);
          console.log(`[ssl] Retry poll: status ${retryRes.status}`);
          if (!retryRes.ok) {
            return {
              module: 'ssl',
              success: true,
              findings: [{
                module: 'ssl',
                severity: 'info',
                title_lt: 'SSL Labs paslauga šiuo metu perkrauta',
                description_lt: `SSL Labs API šiuo metu yra perkrautas ir negali atlikti analizės domenui ${domain}. Tai yra laikina problema iš SSL Labs pusės.`,
                recommendation_lt: 'Pakartokite skenavimą vėliau, kad gautumėte SSL/TLS rezultatus.',
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
              module: 'ssl',
              severity: 'info',
              title_lt: 'SSL Labs API limitas pasiektas',
              description_lt: `SSL Labs API užklausų limitas pasiektas skenojant domeną ${domain}. Tai yra laikina problema.`,
              recommendation_lt: 'Pakartokite skenavimą vėliau.',
              nis2_article: null,
              evidence: { domain, status: 429 },
            }],
          };
        } else if (!res.ok) {
          return { module: 'ssl', success: false, findings: [], error: `SSL Labs API returned: ${res.status}` };
        } else {
          data = await res.json();
        }

        if (data.status === 'READY' || data.status === 'ERROR') {
          break;
        }

        if (poll < MAX_POLLS - 1) {
          console.log(`[ssl] Analysis in progress (${data.status}), polling in ${POLL_INTERVAL_MS / 1000}s...`);
          await sleep(POLL_INTERVAL_MS);
        }
      }
    }

    const findings: ScannerFinding[] = [];

    // Still not ready after all polls
    if (data.status === 'IN_PROGRESS' || data.status === 'DNS') {
      console.log(`[ssl] Timeout: analysis still in progress after ${MAX_POLLS} polls`);
      findings.push({
        module: 'ssl',
        severity: 'info',
        title_lt: 'SSL/TLS analizė dar nebaigta',
        description_lt: `SSL Labs analizė domenui ${domain} buvo pradėta, bet dar nebaigta. Rezultatai bus pasiekiami kitame skenavime.`,
        recommendation_lt: 'Pakartokite skenavimą po kelių minučių, kad gautumėte pilnus SSL/TLS rezultatus.',
        nis2_article: null,
        evidence: { domain, status: data.status },
      });
      return { module: 'ssl', success: true, findings };
    }

    if (data.status === 'ERROR') {
      findings.push({
        module: 'ssl',
        severity: 'high',
        title_lt: 'SSL/TLS sertifikatas nerastas arba nepasiekiamas',
        description_lt: `Domenas ${domain} neturi galiojančio SSL/TLS sertifikato arba serveris nepasiekiamas per HTTPS. Tai reiškia, kad duomenys tarp naudotojo ir serverio perduodami nešifruotai.`,
        recommendation_lt: 'Nedelsiant įdiekite SSL/TLS sertifikatą. Rekomenduojame naudoti nemokamą Let\'s Encrypt sertifikatą.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: { domain, status: data.status, statusMessage: data.statusMessage },
      });
      return { module: 'ssl', success: true, findings };
    }

    // Process endpoints
    const endpoints = (data.endpoints || []) as Array<Record<string, unknown>>;
    for (const endpoint of endpoints) {
      if (endpoint.statusMessage === 'Ready') {
        const grade = (endpoint.grade as string) || 'Unknown';

        if (grade === 'F' || grade === 'T') {
          findings.push({
            module: 'ssl',
            severity: 'critical',
            title_lt: `SSL/TLS vertinimas: ${grade} — kritinės problemos`,
            description_lt: `Serveris ${endpoint.ipAddress} (${domain}) gavo SSL Labs vertinimą „${grade}". Tai reiškia, kad sertifikatas yra negaliojantis, pasibaigęs arba turi rimtų konfigūracijos problemų.`,
            recommendation_lt: 'Skubiai patikrinkite ir atnaujinkite SSL/TLS sertifikatą. Įsitikinkite, kad naudojami šiuolaikiniai šifravimo protokolai (TLS 1.2 arba naujesnė versija).',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { domain, ip: endpoint.ipAddress, grade, details: endpoint.details },
          });
        } else if (grade === 'C' || grade === 'D' || grade === 'E') {
          findings.push({
            module: 'ssl',
            severity: 'high',
            title_lt: `SSL/TLS vertinimas: ${grade} — reikia pataisymų`,
            description_lt: `Serveris ${endpoint.ipAddress} (${domain}) gavo SSL Labs vertinimą „${grade}". Tai rodo silpną šifravimo konfigūraciją, kuri gali būti pažeidžiama.`,
            recommendation_lt: 'Atnaujinkite SSL/TLS konfigūraciją: išjunkite senus protokolus (SSLv3, TLS 1.0, TLS 1.1), naudokite tik stiprius šifrus.',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { domain, ip: endpoint.ipAddress, grade },
          });
        } else if (grade === 'B') {
          findings.push({
            module: 'ssl',
            severity: 'medium',
            title_lt: `SSL/TLS vertinimas: ${grade} — galimi patobulinimai`,
            description_lt: `Serveris ${endpoint.ipAddress} (${domain}) gavo SSL Labs vertinimą „${grade}". Konfigūracija priimtina, bet galima pagerinti.`,
            recommendation_lt: 'Apsvarstykite SSL/TLS konfigūracijos optimizavimą: HSTS antraštės, OCSP stapling, modernių šifrų prioritetizavimas.',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { domain, ip: endpoint.ipAddress, grade },
          });
        } else if (grade === 'A' || grade === 'A+') {
          findings.push({
            module: 'ssl',
            severity: 'info',
            title_lt: `SSL/TLS vertinimas: ${grade} — puiki konfigūracija`,
            description_lt: `Serveris ${endpoint.ipAddress} (${domain}) gavo aukščiausią SSL Labs vertinimą „${grade}". SSL/TLS konfigūracija atitinka geriausias praktikas.`,
            recommendation_lt: 'Tęskite periodinį stebėjimą ir laiku atnaujinkite sertifikatą.',
            nis2_article: null,
            evidence: { domain, ip: endpoint.ipAddress, grade },
          });
        }
      }
    }

    // Check certificate expiry from cert data
    const certs = (data.certs || []) as Array<{ notAfter?: number }>;
    for (const cert of certs) {
      if (cert.notAfter) {
        const expiryDate = new Date(cert.notAfter);
        const now = new Date();
        const daysUntilExpiry = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry < 0) {
          findings.push({
            module: 'ssl',
            severity: 'critical',
            title_lt: 'SSL/TLS sertifikatas pasibaigęs',
            description_lt: `Domeno ${domain} SSL/TLS sertifikatas pasibaigė prieš ${Math.abs(daysUntilExpiry)} dienų (${formatLithuanianDate(expiryDate)}). Naudotojai matys saugumo įspėjimą naršyklėje.`,
            recommendation_lt: 'Nedelsiant atnaujinkite SSL/TLS sertifikatą.',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { domain, expiry_date: expiryDate.toISOString(), days_until_expiry: daysUntilExpiry },
          });
        } else if (daysUntilExpiry <= 30) {
          findings.push({
            module: 'ssl',
            severity: 'high',
            title_lt: `SSL/TLS sertifikatas baigiasi po ${daysUntilExpiry} dienų`,
            description_lt: `Domeno ${domain} SSL/TLS sertifikatas baigsis ${formatLithuanianDate(expiryDate)} (po ${daysUntilExpiry} dienų). Jei sertifikatas nebus atnaujintas laiku, naudotojai negalės saugiai pasiekti svetainės.`,
            recommendation_lt: 'Skubiai atnaujinkite SSL/TLS sertifikatą. Rekomenduojame nustatyti automatinį sertifikatų atnaujinimą.',
            nis2_article: '11 str. 2 d. 5 p.',
            evidence: { domain, expiry_date: expiryDate.toISOString(), days_until_expiry: daysUntilExpiry },
          });
        }
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
