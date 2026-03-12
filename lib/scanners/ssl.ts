import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

/**
 * SSL Labs scanner — checks certificate validity, expiry, cipher strength.
 * Severity: Critical if expired, High if expiring <30 days or weak cipher.
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 * Note: SSL Labs API is free and doesn't require an API key.
 */
export async function scanSsl(domain: string): Promise<ScannerResult> {
  try {
    // Start analysis (startNew=on forces new scan, but we use fromCache=on for speed)
    const analyzeRes = await fetchWithTimeout(
      `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&fromCache=on&maxAge=24&all=done`,
    );

    if (!analyzeRes.ok) {
      return { module: 'ssl', success: false, findings: [], error: `SSL Labs API returned: ${analyzeRes.status}` };
    }

    const data = await analyzeRes.json();
    const findings: ScannerFinding[] = [];

    // If analysis not ready, try polling once more
    if (data.status === 'IN_PROGRESS' || data.status === 'DNS') {
      // Start a new scan and report what we know
      await fetchWithTimeout(
        `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&startNew=on`,
      );

      findings.push({
        module: 'ssl',
        severity: 'info',
        title_lt: 'SSL/TLS analizė vykdoma',
        description_lt: `SSL Labs analizė domenui ${domain} buvo pradėta. Rezultatai bus pasiekiami kitame skenavime.`,
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
    const endpoints = data.endpoints || [];
    for (const endpoint of endpoints) {
      if (endpoint.statusMessage === 'Ready') {
        const grade = endpoint.grade || 'Unknown';

        // Check grade
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
    if (data.certs && data.certs.length > 0) {
      for (const cert of data.certs) {
        const notAfter = cert.notAfter;
        if (notAfter) {
          const expiryDate = new Date(notAfter);
          const now = new Date();
          const daysUntilExpiry = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          if (daysUntilExpiry < 0) {
            findings.push({
              module: 'ssl',
              severity: 'critical',
              title_lt: 'SSL/TLS sertifikatas pasibaigęs',
              description_lt: `Domeno ${domain} SSL/TLS sertifikatas pasibaigė prieš ${Math.abs(daysUntilExpiry)} dienų (${expiryDate.toLocaleDateString('lt-LT')}). Naudotojai matys saugumo įspėjimą naršyklėje.`,
              recommendation_lt: 'Nedelsiant atnaujinkite SSL/TLS sertifikatą.',
              nis2_article: '11 str. 2 d. 5 p.',
              evidence: { domain, expiry_date: expiryDate.toISOString(), days_until_expiry: daysUntilExpiry },
            });
          } else if (daysUntilExpiry <= 30) {
            findings.push({
              module: 'ssl',
              severity: 'high',
              title_lt: `SSL/TLS sertifikatas baigiasi po ${daysUntilExpiry} dienų`,
              description_lt: `Domeno ${domain} SSL/TLS sertifikatas baigsis ${expiryDate.toLocaleDateString('lt-LT')} (po ${daysUntilExpiry} dienų). Jei sertifikatas nebus atnaujintas laiku, naudotojai negalės saugiai pasiekti svetainės.`,
              recommendation_lt: 'Skubiai atnaujinkite SSL/TLS sertifikatą. Rekomenduojame nustatyti automatinį sertifikatų atnaujinimą.',
              nis2_article: '11 str. 2 d. 5 p.',
              evidence: { domain, expiry_date: expiryDate.toISOString(), days_until_expiry: daysUntilExpiry },
            });
          }
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
