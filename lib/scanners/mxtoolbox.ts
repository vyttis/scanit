import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';
import { resolve } from 'dns/promises';

/**
 * MX/DNS scanner — comprehensive email security check.
 * Uses direct DNS lookups for reliability + MXToolbox API when available.
 *
 * Checks:
 * 1. MX records — existence, priorities, configuration
 * 2. SPF — record exists, valid syntax, lookup count, policy strength
 * 3. DKIM — common selectors checked (default, google, microsoft, mail, smtp, selector1, selector2)
 * 4. DMARC — policy, reporting, percentage
 * 5. Blacklist check — major DNSBL services
 * 6. SMTP banner (via MXToolbox API if key available)
 *
 * Severity: Critical if on blacklist or open relay, High if no DMARC/SPF, Medium if misconfigured
 * KSĮ: Art. 11(2)(i) — tapatumo nustatymo priemonės
 */
export async function scanMxtoolbox(domain: string): Promise<ScannerResult> {
  try {
    const findings: ScannerFinding[] = [];
    const mxtoolboxApiKey = process.env.MXTOOLBOX_API_KEY?.trim();

    // ── 1. MX Records ────────────────────────────────────────────────
    let mxRecords: Array<{ exchange: string; priority: number }> = [];
    let hasMx = false;
    try {
      const mx = await resolve(domain, 'MX');
      mxRecords = mx.map((r: { exchange: string; priority: number }) => ({
        exchange: r.exchange,
        priority: r.priority,
      }));
      hasMx = mxRecords.length > 0;
    } catch {
      // No MX records
    }

    if (!hasMx) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'medium',
        title_lt: 'MX įrašai nerasti — domenas negali gauti el. laiškų',
        description_lt:
          `Domenas ${domain} neturi MX (Mail Exchange) įrašų. Tai reiškia, kad šis domenas negali gauti el. laiškų. ` +
          `Jei domenas naudojamas el. paštui, tai yra konfigūracijos problema.`,
        recommendation_lt: 'Jei naudojate šį domeną el. paštui, pridėkite MX įrašus DNS konfigūracijoje pagal el. pašto tiekėjo instrukcijas.',
        nis2_article: null,
        evidence: { domain, mx_found: false },
      });
    } else {
      // Check for suspicious MX configurations
      const mxDomains = mxRecords.map((r) => r.exchange.toLowerCase());
      const isGoogleWorkspace = mxDomains.some((d) => d.includes('google') || d.includes('gmail'));
      const isMicrosoft365 = mxDomains.some((d) => d.includes('outlook') || d.includes('microsoft'));

      findings.push({
        module: 'mxtoolbox',
        severity: 'info',
        title_lt: `MX konfigūracija — ${mxRecords.length} įrašai`,
        description_lt:
          `Domenas ${domain} turi ${mxRecords.length} MX įrašų:\n` +
          mxRecords.map((r) => `• ${r.exchange} (prioritetas: ${r.priority})`).join('\n') +
          `\n\n${isGoogleWorkspace ? 'El. paštas aptarnaujamas Google Workspace.' : ''}` +
          `${isMicrosoft365 ? 'El. paštas aptarnaujamas Microsoft 365.' : ''}`,
        recommendation_lt: 'MX konfigūracija atrodo tvarkinga.',
        nis2_article: null,
        evidence: { domain, mx_records: mxRecords },
      });
    }

    // ── 2. SPF Record ────────────────────────────────────────────────
    let spfFound = false;
    let spfRecord = '';
    let spfRecords: string[] = [];
    try {
      const txtRecords = await resolve(domain, 'TXT');
      const flatRecords = txtRecords.map((r: string[]) => r.join(''));
      spfRecords = flatRecords.filter((r: string) => r.startsWith('v=spf1'));
      if (spfRecords.length > 0) {
        spfFound = true;
        spfRecord = spfRecords[0];
      }
    } catch {
      // No TXT records
    }

    if (!spfFound) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'high',
        title_lt: 'SPF įrašas nerastas — bet kas gali siųsti laiškus jūsų vardu',
        description_lt:
          `Domenas ${domain} neturi SPF (Sender Policy Framework) įrašo. ` +
          `Be SPF, bet kas pasaulyje gali siųsti el. laiškus apsimesdamas jūsų organizacija — gavėjai negalės atskirti tikrų laiškų nuo suklastotų. ` +
          `Tai sudaro sąlygas sukčiavimo atakoms (phishing), kai piktavaliai siunčia laiškus jūsų vardu jūsų klientams, partneriams ar darbuotojams.`,
        recommendation_lt:
          `1. Pridėkite SPF TXT įrašą prie domeno DNS.\n` +
          `2. Pavyzdys Google Workspace: v=spf1 include:_spf.google.com -all\n` +
          `3. Pavyzdys Microsoft 365: v=spf1 include:spf.protection.outlook.com -all\n` +
          `4. SVARBU: naudokite "-all" (hardfail), ne "~all" (softfail).\n` +
          `5. Terminas: per 7 dienas.`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: { domain, spf_found: false },
      });
    } else {
      // Multiple SPF records
      if (spfRecords.length > 1) {
        findings.push({
          module: 'mxtoolbox',
          severity: 'medium',
          title_lt: `Keli SPF įrašai (${spfRecords.length}) — konfigūracijos klaida`,
          description_lt:
            `Domenas ${domain} turi ${spfRecords.length} SPF įrašus. Pagal RFC 7208, domenas turi turėti tik VIENĄ SPF įrašą. ` +
            `Keli SPF įrašai sukelia el. pašto pristatymo problemas — dalis laiškų gali būti atmetami arba patekti į šlamšto aplanką.`,
          recommendation_lt: 'Sujunkite visus SPF įrašus į vieną TXT įrašą, prasidedantį „v=spf1".',
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: { domain, spf_records: spfRecords },
        });
      }

      // Check SPF policy strength
      if (spfRecord.includes('+all')) {
        findings.push({
          module: 'mxtoolbox',
          severity: 'high',
          title_lt: 'SPF leidžia VISUS siuntėjus (+all) — kritinė klaida',
          description_lt:
            `Domeno ${domain} SPF įrašas naudoja „+all", kas reiškia, kad VISI serveriai pasaulyje gali siųsti el. laiškus jūsų domeno vardu. ` +
            `Tai yra ekvivalentu neturėti SPF — jokios apsaugos nuo el. pašto suklastojimo.`,
          recommendation_lt: 'SKUBIAI pakeiskite SPF įrašo pabaigą iš „+all" į „-all".',
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: { domain, spf: spfRecord },
        });
      } else if (spfRecord.includes('~all')) {
        findings.push({
          module: 'mxtoolbox',
          severity: 'medium',
          title_lt: 'SPF naudoja silpną politiką (~all)',
          description_lt:
            `Domeno ${domain} SPF naudoja „~all" (softfail) — suklastoti laiškai bus pažymėti, bet ne visada blokuojami. ` +
            `Tai yra geresnis variantas nei „+all", bet nesuteikia pilnos apsaugos.`,
          recommendation_lt: 'Pakeiskite „~all" į „-all" (hardfail), kad suklastoti laiškai būtų blokuojami.',
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: { domain, spf: spfRecord },
        });
      } else if (spfRecord.includes('?all')) {
        findings.push({
          module: 'mxtoolbox',
          severity: 'medium',
          title_lt: 'SPF naudoja neutralią politiką (?all)',
          description_lt:
            `Domeno ${domain} SPF naudoja „?all" (neutral) — tai reiškia, kad SPF netikrina siuntėjų.`,
          recommendation_lt: 'Pakeiskite „?all" į „-all".',
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: { domain, spf: spfRecord },
        });
      }

      // Count DNS lookups in SPF (max 10 per RFC)
      const spfMechanisms = spfRecord.match(/(include:|a:|mx:|ptr:|redirect=)/gi) || [];
      if (spfMechanisms.length > 10) {
        findings.push({
          module: 'mxtoolbox',
          severity: 'medium',
          title_lt: `SPF viršija DNS peržvalgų limitą — ${spfMechanisms.length}/10`,
          description_lt:
            `SPF įrašas turi ${spfMechanisms.length} DNS peržvalgų mechanizmų, bet RFC 7208 leidžia maksimum 10. ` +
            `Viršijus limitą, SPF gali nustoti veikti — laiškai bus atmesti arba pažymėti kaip šlamštas.`,
          recommendation_lt:
            `1. Optimizuokite SPF — sujunkite „include" direktyvas.\n` +
            `2. Pašalinkite nebenaudojamus siuntimo šaltinius.\n` +
            `3. Apsvarstykite SPF makrokomandų naudojimą.`,
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: { domain, spf: spfRecord, lookup_count: spfMechanisms.length },
        });
      }
    }

    // ── 3. DKIM Check ────────────────────────────────────────────────
    const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'mail', 'smtp', 'dkim', 'k1', 's1', 's2'];
    const foundDkim: Array<{ selector: string; record: string }> = [];

    const dkimChecks = await Promise.allSettled(
      dkimSelectors.map(async (selector) => {
        try {
          const records = await resolve(`${selector}._domainkey.${domain}`, 'TXT');
          const flat = records.map((r: string[]) => r.join('')).filter((r: string) => r.includes('v=DKIM1') || r.includes('p='));
          if (flat.length > 0) {
            return { selector, record: flat[0] };
          }
        } catch {
          // No DKIM for this selector
        }
        return null;
      }),
    );

    for (const result of dkimChecks) {
      if (result.status === 'fulfilled' && result.value) {
        foundDkim.push(result.value);
      }
    }

    if (foundDkim.length === 0) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'medium',
        title_lt: 'DKIM įrašai nerasti — laiškai gali būti nepristatyti',
        description_lt:
          `Domenas ${domain} neturi DKIM (DomainKeys Identified Mail) įrašų (patikrinti selektoriai: ${dkimSelectors.join(', ')}). ` +
          `DKIM kriptografiškai pasirašo kiekvieną laišką, įrodydamas, kad jis tikrai buvo išsiųstas iš jūsų serverio. ` +
          `Be DKIM, jūsų laiškai gali patekti į šlamšto aplanką, ypač su DMARC politika.`,
        recommendation_lt:
          `1. Įjunkite DKIM savo el. pašto tiekėjo administravimo pulte.\n` +
          `2. Google Workspace: Admin → Apps → Gmail → Authenticate email → Generate new record.\n` +
          `3. Microsoft 365: Exchange admin center → Authentication → DKIM.\n` +
          `4. Pridėkite sugeneruotą TXT įrašą prie DNS.`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: { domain, dkim_found: false, selectors_checked: dkimSelectors },
      });
    } else {
      findings.push({
        module: 'mxtoolbox',
        severity: 'info',
        title_lt: `DKIM sukonfigūruotas — ${foundDkim.length} selektoriai`,
        description_lt:
          `Domenas ${domain} turi DKIM įrašus: ${foundDkim.map((d) => d.selector).join(', ')}. ` +
          `Laiškai yra kriptografiškai pasirašomi, kas patvirtina jų autentiškumą.`,
        recommendation_lt: 'DKIM konfigūracija tvarkinga — jokių veiksmų nereikia.',
        nis2_article: null,
        evidence: { domain, dkim_selectors: foundDkim.map((d) => d.selector) },
      });
    }

    // ── 4. DMARC Check ───────────────────────────────────────────────
    let dmarcFound = false;
    let dmarcRecord = '';
    try {
      const dmarcRecords = await resolve(`_dmarc.${domain}`, 'TXT');
      const flatDmarc = dmarcRecords.map((r: string[]) => r.join(''));
      const dmarc = flatDmarc.find((r: string) => r.startsWith('v=DMARC1'));
      if (dmarc) {
        dmarcFound = true;
        dmarcRecord = dmarc;
      }
    } catch {
      // No DMARC record
    }

    if (!dmarcFound) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'high',
        title_lt: 'DMARC įrašas nerastas — nėra apsaugos nuo el. pašto suklastojimo',
        description_lt:
          `Domenas ${domain} neturi DMARC (Domain-based Message Authentication, Reporting and Conformance) įrašo. ` +
          `Be DMARC, negalima efektyviai kontroliuoti, kas siunčia el. laiškus jūsų domeno vardu. ` +
          `Piktavaliai gali laisvai siųsti suklastotus laiškus, apsimesdami jūsų organizacija, ` +
          `ir apgaudinėti jūsų klientus, partnerius ir darbuotojus.\n\n` +
          `DMARC yra būtinas SPF ir DKIM papildymas — be jo, net turėdami SPF ir DKIM, negalite užtikrinti, kad suklastoti laiškai bus blokuojami.`,
        recommendation_lt:
          `1. Pridėkite DMARC TXT įrašą: _dmarc.${domain}\n` +
          `2. Pradinė reikšmė: v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}\n` +
          `3. Stebėkite ataskaitas 2-4 savaites.\n` +
          `4. Pereikite prie p=quarantine, po to p=reject.\n` +
          `5. Terminas: per 14 dienų.`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: { domain, dmarc_found: false },
      });
    } else {
      // Parse DMARC policy
      const policyMatch = dmarcRecord.match(/;\s*p=(none|quarantine|reject)/i);
      const policy = policyMatch ? policyMatch[1].toLowerCase() : 'unknown';
      const ruaMatch = dmarcRecord.match(/rua=([^;]+)/);
      const rufMatch = dmarcRecord.match(/ruf=([^;]+)/);
      const pctMatch = dmarcRecord.match(/pct=(\d+)/);
      const pct = pctMatch ? parseInt(pctMatch[1]) : 100;
      const spMatch = dmarcRecord.match(/sp=(none|quarantine|reject)/i);
      const subPolicy = spMatch ? spMatch[1].toLowerCase() : null;
      const hasRua = !!ruaMatch;
      const hasRuf = !!rufMatch;

      if (policy === 'none') {
        findings.push({
          module: 'mxtoolbox',
          severity: 'high',
          title_lt: 'DMARC politika „none" — tik stebėjimas, apsaugos nėra',
          description_lt:
            `Domeno ${domain} DMARC politika yra „none" — el. pašto serveriai tik praneša apie pažeidimus, bet NEBLOKUOJA suklastotų laiškų. ` +
            `Tai reiškia, kad piktavaliai vis dar gali laisvai siųsti suklastotus laiškus jūsų domeno vardu.\n\n` +
            `Nors tai yra geras pirmas žingsnis (leidžia stebėti situaciją), jis neapsaugo nuo sukčiavimo.\n` +
            `${hasRua ? `Ataskaitos siunčiamos į: ${ruaMatch![1]}` : 'Ataskaitų adresatas (rua) nenurodytas!'}`,
          recommendation_lt:
            `1. Peržiūrėkite DMARC ataskaitas (rua) 2-4 savaites.\n` +
            `2. Įsitikinkite, kad visi teisėti siuntimo šaltiniai yra SPF/DKIM sąraše.\n` +
            `3. Pereikite prie p=quarantine (suklastoti laiškai bus perkelti į šlamštą).\n` +
            `4. Galutinis tikslas: p=reject (suklastoti laiškai bus visiškai atmesti).`,
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: { domain, dmarc: dmarcRecord, policy, rua: ruaMatch?.[1], ruf: rufMatch?.[1], pct },
        });
      } else if (policy === 'quarantine' || policy === 'reject') {
        const issues: string[] = [];
        if (pct < 100) issues.push(`pct=${pct} — tik ${pct}% laiškų tikrinami`);
        if (!hasRua) issues.push('Nėra rua (aggregate reports) adresato');
        if (subPolicy === 'none') issues.push('Subdomenų politika (sp) yra „none"');

        if (issues.length > 0) {
          findings.push({
            module: 'mxtoolbox',
            severity: 'medium',
            title_lt: `DMARC politika „${policy}" su trūkumais`,
            description_lt:
              `DMARC politika „${policy}" yra gera, bet turi šių trūkumų:\n` +
              issues.map((i) => `• ${i}`).join('\n'),
            recommendation_lt:
              `${pct < 100 ? `1. Padidinkite pct iki 100 (dabar tik ${pct}% laiškų tikrinami).\n` : ''}` +
              `${!hasRua ? '2. Pridėkite rua adresą DMARC ataskaitoms gauti.\n' : ''}` +
              `${subPolicy === 'none' ? '3. Nustatykite sp=reject subdomenams.\n' : ''}`,
            nis2_article: '11 str. 2 d. 9 p.',
            evidence: { domain, dmarc: dmarcRecord, policy, pct, has_rua: hasRua, has_ruf: hasRuf, sub_policy: subPolicy },
          });
        } else {
          findings.push({
            module: 'mxtoolbox',
            severity: 'info',
            title_lt: `DMARC politika: ${policy} — puiki apsauga`,
            description_lt:
              `DMARC su politika „${policy}" — niekas negali siųsti suklastotų el. laiškų jūsų domenu @${domain}. ` +
              `Gavėjų el. pašto serveriai juos ${policy === 'reject' ? 'automatiškai atmeta' : 'perkelia į šlamšto aplanką'}.\n\n` +
              `${hasRua ? 'Ataskaitos konfigūruotos ✓' : ''}  ${hasRuf ? 'Forensic ataskaitos ✓' : ''}\n` +
              `Tai viena svarbiausių el. pašto saugumo priemonių.`,
            recommendation_lt: 'Konfigūracija puiki. Periodiškai tikrinkite DMARC ataskaitas.',
            nis2_article: null,
            evidence: { domain, dmarc: dmarcRecord, policy, pct, has_rua: hasRua, has_ruf: hasRuf },
          });
        }

        if (!hasRuf) {
          findings.push({
            module: 'mxtoolbox',
            severity: 'low',
            title_lt: 'DMARC forensic ataskaitos (ruf) nesukonfigūruotos',
            description_lt:
              `DMARC neturi ruf (forensic report) adresato. Forensic ataskaitos leidžia matyti konkrečius suklastotų laiškų pavyzdžius.`,
            recommendation_lt: 'Pridėkite ruf= parametrą prie DMARC įrašo.',
            nis2_article: null,
            evidence: { domain, dmarc: dmarcRecord, has_ruf: false },
          });
        }
      }
    }

    // ── 5. DNSBL Blacklist Check ─────────────────────────────────────
    let domainIps: string[] = [];
    try {
      domainIps = await resolve(domain, 'A');
    } catch {
      // Can't resolve
    }

    const mxIps: string[] = [];
    for (const mx of mxRecords.slice(0, 3)) {
      try {
        const ips = await resolve(mx.exchange, 'A');
        mxIps.push(...ips);
      } catch {
        // Can't resolve MX IP
      }
    }

    const allIpsToCheck = Array.from(new Set([...domainIps, ...mxIps])).slice(0, 5);
    const blacklists = [
      'zen.spamhaus.org',
      'bl.spamcop.net',
      'b.barracudacentral.org',
      'dnsbl.sorbs.net',
      'spam.dnsbl.sorbs.net',
    ];

    const blacklistedOn: Array<{ ip: string; blacklist: string }> = [];

    if (allIpsToCheck.length > 0) {
      const blChecks = await Promise.allSettled(
        allIpsToCheck.flatMap((ip) =>
          blacklists.map(async (bl) => {
            const reversed = ip.split('.').reverse().join('.');
            try {
              await resolve(`${reversed}.${bl}`, 'A');
              return { ip, blacklist: bl };
            } catch {
              return null;
            }
          }),
        ),
      );

      for (const result of blChecks) {
        if (result.status === 'fulfilled' && result.value) {
          blacklistedOn.push(result.value);
        }
      }
    }

    if (blacklistedOn.length > 0) {
      const blList = blacklistedOn.map((b) => `• ${b.ip} — ${b.blacklist}`).join('\n');
      const isSpamhaus = blacklistedOn.some((b) => b.blacklist.includes('spamhaus'));

      findings.push({
        module: 'mxtoolbox',
        severity: isSpamhaus ? 'critical' : 'high',
        title_lt: `IP adresai juoduosiuose sąrašuose — ${blacklistedOn.length} įrašai`,
        description_lt:
          `Jūsų domeno arba el. pašto serverio IP adresai rasti juoduosiuose sąrašuose (blacklists):\n${blList}\n\n` +
          `Tai reiškia, kad jūsų siunčiami el. laiškai gali būti automatiškai blokuojami arba patekti į gavėjų šlamšto aplankus. ` +
          `${isSpamhaus ? 'Spamhaus yra vienas svarbiausių blacklist — daugelis el. pašto serverių jo atmetimą traktuoja kaip galutinį.' : ''}\n\n` +
          `Priežastys: ankstesnis spam siuntimas, serverio pažeidimas, arba IP paveldėtas iš ankstesnio savininko.`,
        recommendation_lt:
          `1. Patikrinkite, ar serveris nesiunčia spam laiškų (gali būti pažeistas).\n` +
          `2. Kreipkitės į kiekvieną blacklist operatorių dėl IP pašalinimo (delisting).\n` +
          `3. Spamhaus: https://www.spamhaus.org/lookup/ — pateikite pašalinimo prašymą.\n` +
          `4. Patikrinkite, ar SPF/DKIM/DMARC teisingai sukonfigūruoti.`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: { domain, blacklisted_entries: blacklistedOn, checked_ips: allIpsToCheck },
      });
    }

    // ── 6. MXToolbox API checks (if key available) ───────────────────
    if (mxtoolboxApiKey) {
      try {
        const smtpRes = await fetchWithTimeout(
          `https://mxtoolbox.com/api/v1/lookup/smtp/${encodeURIComponent(domain)}`,
          { headers: { Authorization: mxtoolboxApiKey } },
          10_000,
        );
        if (smtpRes.ok) {
          const smtpData = await smtpRes.json();
          const failed = (smtpData.Failed || []) as Array<{ Name: string; Info: string }>;
          const warnings = (smtpData.Warnings || []) as Array<{ Name: string; Info: string }>;

          const openRelay = failed.some((f) => f.Name?.toLowerCase().includes('open relay'));
          if (openRelay) {
            findings.push({
              module: 'mxtoolbox',
              severity: 'critical',
              title_lt: 'Atviras el. pašto perdavimas (open relay) — kritinė saugumo spraga',
              description_lt:
                `Domeno ${domain} el. pašto serveris leidžia bet kam siųsti laiškus per jūsų serverį (open relay). ` +
                `Tai reiškia, kad piktavaliai gali naudoti jūsų serverį spam ir sukčiavimo laiškų siuntimui.`,
              recommendation_lt:
                `1. SKUBIAI (per 24 val.): sukonfigūruokite SMTP serverį taip, kad jis priimtų laiškus tik iš autorizuotų siuntėjų.\n` +
                `2. Patikrinkite autentifikacijos reikalavimus SMTP serveryje.`,
              nis2_article: '11 str. 2 d. 9 p.',
              evidence: { domain, smtp_failures: failed, open_relay: true },
            });
          }

          if (warnings.length > 0 && !openRelay) {
            findings.push({
              module: 'mxtoolbox',
              severity: 'low',
              title_lt: `SMTP konfigūracijos įspėjimai — ${warnings.length} vnt.`,
              description_lt:
                `SMTP tikrinimas parodė ${warnings.length} įspėjimų:\n` +
                warnings.map((w) => `• ${w.Name}: ${w.Info}`).join('\n'),
              recommendation_lt: 'Peržiūrėkite SMTP konfigūraciją ir pašalinkite įspėjimus.',
              nis2_article: null,
              evidence: { domain, smtp_warnings: warnings },
            });
          }
        }
      } catch {
        // MXToolbox API not available
      }
    }

    // ── Summary: all good ────────────────────────────────────────────
    const nonInfoFindings = findings.filter((f) => f.severity !== 'info');
    if (nonInfoFindings.length === 0 && spfFound && dmarcFound && foundDkim.length > 0 && blacklistedOn.length === 0) {
      findings.push({
        module: 'mxtoolbox',
        severity: 'info',
        title_lt: 'El. pašto saugumo konfigūracija — viskas tvarkoje',
        description_lt:
          `Domeno ${domain} el. pašto saugumo konfigūracija atitinka geriausias praktikas.\n` +
          `✓ SPF — ${spfRecord.includes('-all') ? 'griežta politika (-all)' : 'sukonfigūruota'}\n` +
          `✓ DKIM — ${foundDkim.length} selektoriai\n` +
          `✓ DMARC — ${dmarcRecord.includes('p=reject') ? 'reject' : dmarcRecord.includes('p=quarantine') ? 'quarantine' : 'sukonfigūruota'}\n` +
          `✓ Blacklists — nerasta\n\n` +
          `Tai reiškia, kad jūsų organizacija yra apsaugota nuo el. pašto sukčiavimo (phishing) atakų.`,
        recommendation_lt: 'Konfigūracija puiki — periodiškai tikrinkite, ar SPF, DKIM ir DMARC įrašai vis dar aktualūs.',
        nis2_article: null,
        evidence: {
          domain, spf: spfRecord,
          dkim_selectors: foundDkim.map((d) => d.selector),
          dmarc: dmarcRecord, mx_records: mxRecords,
          blacklists_clean: true,
        },
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
