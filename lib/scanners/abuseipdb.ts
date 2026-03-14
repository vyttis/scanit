import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { resolve } from 'dns/promises';

/**
 * AbuseIPDB scanner — checks IP abuse reports.
 * Severity: High if abuse confidence >50%.
 * KSĮ: Art. 11(2)(e) — tinklų saugumas
 */
export async function scanAbuseipdb(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.ABUSEIPDB_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'abuseipdb', success: false, findings: [], error: 'ABUSEIPDB_API_KEY not configured' };
  }

  try {
    // Resolve domain to IP
    let ip: string;
    try {
      const addresses = await resolve(domain, 'A');
      if (addresses.length === 0) {
        return {
          module: 'abuseipdb',
          success: true,
          findings: [{
            module: 'abuseipdb',
            severity: 'info',
            title_lt: 'IP adresas nerastas',
            description_lt: `Domenas ${domain} neturi A įrašo. AbuseIPDB tikrinimas negalimas.`,
            recommendation_lt: 'Patikrinkite DNS konfigūraciją.',
            nis2_article: null,
            evidence: { domain },
          }],
        };
      }
      ip = addresses[0];
    } catch {
      return {
        module: 'abuseipdb',
        success: true,
        findings: [{
          module: 'abuseipdb',
          severity: 'info',
          title_lt: 'DNS rezoliucija nepavyko',
          description_lt: `Nepavyko nustatyti domeno ${domain} IP adreso.`,
          recommendation_lt: 'Patikrinkite DNS konfigūraciją.',
          nis2_article: null,
          evidence: { domain },
        }],
      };
    }

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    console.log(`[abuseipdb] GET ${url}`);
    const res = await fetchWithTimeout(
      url,
      {
        headers: {
          Key: apiKey,
          Accept: 'application/json',
        },
      },
      15_000,
    );

    console.log(`[abuseipdb] Response: ${res.status}`);
    if (!res.ok) {
      // Discard error body — may contain API key echoes or sensitive server info
      await res.text().catch(() => '');
      console.error(`[abuseipdb] Error: HTTP ${res.status}`);
      return { module: 'abuseipdb', success: false, findings: [], error: `AbuseIPDB API returned: ${res.status}` };
    }

    const responseData = await res.json();
    const data = responseData.data;
    const findings: ScannerFinding[] = [];

    const confidenceScore = data.abuseConfidenceScore || 0;
    const totalReports = data.totalReports || 0;

    if (confidenceScore > 50) {
      findings.push({
        module: 'abuseipdb',
        severity: 'high',
        title_lt: `IP adresas turi aukštą piktnaudžiavimo balą — ${confidenceScore}%`,
        description_lt: `IP adresas ${ip} (${domain}) turi ${confidenceScore}% piktnaudžiavimo pasitikėjimo balą AbuseIPDB duomenų bazėje (${totalReports} pranešimų per paskutines 90 dienų). Tai reiškia, kad iš šio IP adreso buvo pranešta apie kenkėjišką veiklą — gali būti, kad serveris yra pažeistas arba naudojamas atakoms.`,
        recommendation_lt: 'Nedelsiant patikrinkite serverio saugumą. Ieškokite neautorizuotos prieigos ar kenkėjiškos programinės įrangos požymių. Apsvarstykite IP adreso pakeitimą.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain, ip, abuse_confidence: confidenceScore, total_reports: totalReports,
          isp: data.isp, country: data.countryCode,
          last_reported: data.lastReportedAt,
        },
      });
    } else if (totalReports > 0) {
      findings.push({
        module: 'abuseipdb',
        severity: 'medium',
        title_lt: `IP adresas turi piktnaudžiavimo pranešimų — ${totalReports} vnt.`,
        description_lt: `IP adresas ${ip} (${domain}) turi ${totalReports} piktnaudžiavimo pranešimų AbuseIPDB duomenų bazėje (pasitikėjimo balas: ${confidenceScore}%). Pranešimų skaičius nėra kritiškai didelis, bet verta stebėti.`,
        recommendation_lt: 'Stebėkite serverio veiklą ir patikrinkite, ar nėra neautorizuotos prieigos požymių.',
        nis2_article: '11 str. 2 d. 5 p.',
        evidence: {
          domain, ip, abuse_confidence: confidenceScore, total_reports: totalReports,
          isp: data.isp, country: data.countryCode,
        },
      });
    } else {
      findings.push({
        module: 'abuseipdb',
        severity: 'info',
        title_lt: 'IP adreso reputacija gera — piktnaudžiavimo nenustatyta',
        description_lt:
          `IP adresas ${ip} (${domain}) neturi jokių piktnaudžiavimo pranešimų tarptautinėje AbuseIPDB duomenų bazėje. ` +
          `Tai reiškia, kad per pastaruosius 90 dienų niekas nepranešė apie kenkėjišką veiklą iš jūsų serverio — ` +
          `jūsų serveris nėra naudojamas atakoms, spam siuntimui ar kitai neteisėtai veiklai.\n\n` +
          `Tai teigiamas ženklas — jūsų serverio saugumas šiuo atžvilgiu yra geras.`,
        recommendation_lt: 'Jokių veiksmų nereikia. Tęskite periodinį stebėjimą — AbuseIPDB tikrinimas padeda anksti pastebėti, jei jūsų serveris būtų pažeistas.',
        nis2_article: null,
        evidence: { domain, ip, abuse_confidence: 0, total_reports: 0 },
      });
    }

    return { module: 'abuseipdb', success: true, findings };
  } catch (err) {
    return {
      module: 'abuseipdb',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
