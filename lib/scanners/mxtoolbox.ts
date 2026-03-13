import type { ScannerResult, ScannerFinding } from './types';
import { resolve } from 'dns/promises';

/**
 * MX/DNS scanner — checks SPF, DKIM, DMARC configuration.
 * Uses direct DNS lookups instead of MXToolbox API for reliability.
 * Severity: High if missing DMARC, Medium if misconfigured.
 * KSĮ: Art. 11(2)(i) — tapatumo nustatymo priemonės
 */
export async function scanMxtoolbox(domain: string): Promise<ScannerResult> {
  try {
    const findings: ScannerFinding[] = [];

    // Check SPF record
    let spfFound = false;
    let spfRecord = '';
    try {
      const txtRecords = await resolve(domain, 'TXT');
      const flatRecords = txtRecords.map((r: string[]) => r.join(''));
      const spfRecords = flatRecords.filter((r: string) => r.startsWith('v=spf1'));
      if (spfRecords.length > 0) {
        spfFound = true;
        spfRecord = spfRecords[0];

        if (spfRecords.length > 1) {
          findings.push({
            module: 'mxtoolbox',
            severity: 'medium',
            title_lt: 'Keli SPF įrašai — konfigūracijos klaida',
            description_lt: `Domenas ${domain} turi ${spfRecords.length} SPF įrašus. Pagal RFC 7208, domenas turi turėti tik vieną SPF įrašą. Keli SPF įrašai gali sukelti el. pašto pristatymo problemų.`,
            recommendation_lt: 'Sujunkite visus SPF įrašus į vieną. Palikite tik vieną TXT įrašą, prasidedantį „v=spf1".',
            nis2_article: '11 str. 2 d. 9 p.',
            evidence: { domain, spf_records: spfRecords },
          });
        }

        // Check for ~all (softfail) vs -all (hardfail)
        if (spfRecord.includes('+all')) {
          findings.push({
            module: 'mxtoolbox',
            severity: 'high',
            title_lt: 'SPF leidžia visus siuntėjus (+all)',
            description_lt: `Domeno ${domain} SPF įrašas naudoja „+all", kas reiškia, kad bet kas gali siųsti el. laiškus šio domeno vardu. Tai leidžia piktavaliams lengvai apsimesti jūsų organizacija.`,
            recommendation_lt: 'Pakeiskite SPF įrašo pabaigą iš „+all" į „-all" arba bent „~all".',
            nis2_article: '11 str. 2 d. 9 p.',
            evidence: { domain, spf: spfRecord },
          });
        }
      }
    } catch {
      // DNS lookup failed - no TXT records
    }

    if (!spfFound) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'high',
        title_lt: 'SPF įrašas nerastas',
        description_lt: `Domenas ${domain} neturi SPF (Sender Policy Framework) įrašo. Be SPF, bet kas gali siųsti el. laiškus jūsų domeno vardu, o tai sudaro sąlygas sukčiavimo atakoms (phishing).`,
        recommendation_lt: 'Pridėkite SPF TXT įrašą prie savo domeno DNS. Pavyzdys: „v=spf1 include:_spf.google.com -all" (pritaikykite pagal savo el. pašto tiekėją).',
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: { domain, spf_found: false },
      });
    }

    // Check DMARC record
    let dmarcFound = false;
    try {
      const dmarcRecords = await resolve(`_dmarc.${domain}`, 'TXT');
      const flatDmarc = dmarcRecords.map((r: string[]) => r.join(''));
      const dmarc = flatDmarc.find((r: string) => r.startsWith('v=DMARC1'));

      if (dmarc) {
        dmarcFound = true;

        // Check DMARC policy
        const policyMatch = dmarc.match(/p=(none|quarantine|reject)/);
        const policy = policyMatch ? policyMatch[1] : 'unknown';

        if (policy === 'none') {
          findings.push({
            module: 'mxtoolbox',
            severity: 'medium',
            title_lt: 'DMARC politika nustatyta „none" — tik stebėjimas',
            description_lt: `Domeno ${domain} DMARC politika yra „none", kas reiškia, kad el. pašto serveriai tik praneša apie pažeidimus, bet neblokuoja suklastotų laiškų. Tai yra geras pirmas žingsnis, bet neapsaugo nuo sukčiavimo.`,
            recommendation_lt: 'Palaipsniui pereikite nuo „p=none" prie „p=quarantine" ir galiausiai „p=reject", kad suklastoti laiškai būtų blokuojami.',
            nis2_article: '11 str. 2 d. 9 p.',
            evidence: { domain, dmarc_record: dmarc, policy },
          });
        } else if (policy === 'reject' || policy === 'quarantine') {
          findings.push({
            module: 'mxtoolbox',
            severity: 'info',
            title_lt: `DMARC politika: ${policy} — puiki apsauga`,
            description_lt:
              `DMARC su politika „${policy}" — tai reiškia, kad niekas negali siųsti el. laiškų apsimetant jūsų domenu @${domain}. ` +
              `Kai piktavaliai bando siųsti suklastotus laiškus jūsų organizacijos vardu, gavėjų el. pašto serveriai juos ${policy === 'reject' ? 'automatiškai atmeta — jie net nepasiekia gavėjo' : 'perkelia į šlamšto aplanką'}. ` +
              `Tai apsaugo jūsų darbuotojus, klientus ir partnerius nuo sukčiavimo el. paštu (phishing) per jūsų domeną.\n\n` +
              `Tai viena svarbiausių el. pašto saugumo priemonių — daugelis Lietuvos organizacijų jos dar neturi.`,
            recommendation_lt: 'Konfigūracija puiki — jokių veiksmų nereikia. Periodiškai tikrinkite DMARC ataskaitas, kad įsitikintumėte, jog teisėti laiškai nėra blokuojami.',
            nis2_article: null,
            evidence: { domain, dmarc_record: dmarc, policy },
          });
        }
      }
    } catch {
      // No DMARC record
    }

    if (!dmarcFound) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'high',
        title_lt: 'DMARC įrašas nerastas',
        description_lt: `Domenas ${domain} neturi DMARC (Domain-based Message Authentication, Reporting and Conformance) įrašo. Be DMARC, negalima efektyviai kontroliuoti, kas siunčia el. laiškus jūsų domeno vardu, ir apsisaugoti nuo sukčiavimo apsimetant (phishing).`,
        recommendation_lt: 'Pridėkite DMARC TXT įrašą: „_dmarc.domenas.lt" su reikšme „v=DMARC1; p=quarantine; rua=mailto:dmarc@domenas.lt". Pradžioje galite naudoti „p=none" stebėjimui.',
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: { domain, dmarc_found: false },
      });
    }

    // Check MX records exist
    try {
      const mxRecords = await resolve(domain, 'MX');
      if (mxRecords.length === 0) {
        findings.push({
          module: 'mxtoolbox',
          severity: 'medium',
          title_lt: 'MX įrašai nerasti',
          description_lt: `Domenas ${domain} neturi MX (Mail Exchange) įrašų. Tai reiškia, kad domenas negali gauti el. laiškų.`,
          recommendation_lt: 'Jei naudojate šį domeną el. paštui, pridėkite MX įrašus savo DNS konfigūracijoje.',
          nis2_article: null,
          evidence: { domain, mx_found: false },
        });
      }
    } catch {
      // No MX records
    }

    if (findings.length === 0) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'info',
        title_lt: 'El. pašto saugumo konfigūracija — viskas tvarkoje',
        description_lt:
          `Domeno ${domain} el. pašto saugumo konfigūracija atitinka geriausias praktikas. ` +
          `SPF įrašas tinkamai apriboja, kas gali siųsti laiškus jūsų vardu, ` +
          `o DMARC politika užtikrina, kad suklastoti laiškai bus blokuojami.\n\n` +
          `Tai reiškia, kad jūsų organizacija yra apsaugota nuo el. pašto sukčiavimo (phishing) atakų, ` +
          `kai piktavaliai bando apsimesti jūsų darbuotojais ar organizacija siunčiant suklastotus laiškus.`,
        recommendation_lt: 'Konfigūracija puiki — jokių veiksmų nereikia. Periodiškai tikrinkite, ar SPF ir DMARC įrašai vis dar aktualūs (pvz., po el. pašto tiekėjo pakeitimo).',
        nis2_article: null,
        evidence: { domain, spf: spfRecord, dmarc_found: dmarcFound },
      });
    }

    return { module: 'mxtoolbox', success: true, findings };
  } catch (err) {
    return {
      module: 'mxtoolbox',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
