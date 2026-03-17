import type { ScannerResult, ScannerFinding, ScannerOptions } from './types';
import { fetchWithTimeout } from './types';

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * HaveIBeenPwned scanner — full breach intelligence.
 * 1. Domain breach search: GET /v3/breacheddomain/{domain}
 *    — All breached accounts per domain with breach names
 * 2. Breach details: GET /v3/breach/{breachname}
 *    — Description, data classes, password exposure, verification
 * 3. Paste search (for common accounts): not used without specific emails
 *
 * Severity: Critical if passwords exposed, High if PII exposed, Medium if emails only
 * KSĮ: Art. 11(2)(i) — prieigos valdymas ir MFA
 */
/**
 * Mask an email address for privacy: john@example.com → j***@example.com
 */
function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return '***@***';
  return `${local[0]}***@${domain}`;
}

export async function scanHibp(domain: string, options?: ScannerOptions): Promise<ScannerResult> {
  const apiKey = process.env.HIBP_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'hibp', success: false, findings: [], error: 'HIBP_API_KEY not configured' };
  }

  const headers = {
    'hibp-api-key': apiKey,
    'user-agent': 'scanit.lt-platform',
  };

  try {
    const findings: ScannerFinding[] = [];

    // ── Step 1: Domain breach search ─────────────────────────────────
    const url = `https://haveibeenpwned.com/api/v3/breacheddomain/${encodeURIComponent(domain)}`;
    console.log(`[hibp] GET breacheddomain/${domain}`);
    const res = await fetchWithTimeout(url, { headers }, 15_000);
    console.log(`[hibp] Response: ${res.status}`);

    if (res.status === 404) {
      // No breaches found for domain
      findings.push({
        module: 'hibp',
        severity: 'info',
        title_lt: 'Duomenų nutekėjimų nerasta',
        description_lt:
          `Domeno ${domain} el. pašto adresai nebuvo rasti jokiose žinomose duomenų nutekėjimo bazėse (patikrinta ${new Date().getFullYear()} m. duomenimis). ` +
          `Tai reiškia, kad jūsų organizacijos darbuotojų el. pašto adresai ir susieti duomenys (slaptažodžiai, asmens duomenys) nėra viešai prieinami iš žinomų nutekėjimų.\n\n` +
          `Tai teigiamas ženklas, tačiau negarantuoja visiškos apsaugos — nauji nutekėjimai aptinkami nuolat.`,
        recommendation_lt: 'Tęskite periodinį stebėjimą. Naudokite stiprius, unikalius slaptažodžius su kelių veiksnių autentifikavimu (MFA).',
        nis2_article: null,
        evidence: { domain, breaches_found: 0, accounts_affected: 0 },
      });
      return { module: 'hibp', success: true, findings };
    }

    if (!res.ok) {
      await res.text().catch(() => '');
      return { module: 'hibp', success: false, findings: [], error: `HIBP API returned: ${res.status}` };
    }

    // breacheddomain returns { "alias1": ["Breach1","Breach2"], "alias2": ["Breach3"] }
    const domainBreaches = await res.json();

    // Collect all unique breach names and affected accounts
    const breachNames = new Set<string>();
    const accountBreachMap: Record<string, string[]> = {};
    let totalAffectedAccounts = 0;

    for (const [alias, breaches] of Object.entries(domainBreaches)) {
      const breachList = breaches as string[];
      accountBreachMap[`${alias}@${domain}`] = breachList;
      totalAffectedAccounts++;
      for (const b of breachList) {
        breachNames.add(b);
      }
    }

    // ── Step 2: Get details for each breach ──────────────────────────
    interface BreachDetail {
      Name: string;
      Title: string;
      Domain: string;
      BreachDate: string;
      AddedDate: string;
      ModifiedDate: string;
      PwnCount: number;
      Description: string;
      DataClasses: string[];
      IsVerified: boolean;
      IsFabricated: boolean;
      IsSensitive: boolean;
      IsRetired: boolean;
      IsSpamList: boolean;
    }

    const breachDetails: BreachDetail[] = [];
    const breachNamesArr = Array.from(breachNames);

    // Fetch details for each breach (max 15 to stay within limits, with rate limiting)
    for (const breachName of breachNamesArr.slice(0, 15)) {
      try {
        const detailRes = await fetchWithTimeout(
          `https://haveibeenpwned.com/api/v3/breach/${encodeURIComponent(breachName)}`,
          { headers },
          10_000,
        );
        if (detailRes.ok) {
          const detail = await detailRes.json();
          breachDetails.push(detail);
        }
        // HIBP rate limit: 1 request per 1.5s
        await sleep(1600);
      } catch {
        // Non-critical
      }
    }

    // Categorize data classes across all breaches
    const allDataClasses = new Set<string>();
    let hasPasswords = false;
    let hasPhoneNumbers = false;
    let hasPhysicalAddresses = false;
    let hasDOB = false;
    let hasFinancialData = false;

    const passwordBreaches: BreachDetail[] = [];
    const piiBreaches: BreachDetail[] = [];
    const emailOnlyBreaches: BreachDetail[] = [];

    for (const breach of breachDetails) {
      const classes = breach.DataClasses || [];
      for (const dc of classes) {
        allDataClasses.add(dc);
      }

      const classesLower = classes.map((c: string) => c.toLowerCase());
      const hasPasswordInBreach = classesLower.some((c: string) =>
        c.includes('password') || c.includes('slaptažod'),
      );
      const hasPiiInBreach = classesLower.some((c: string) =>
        c.includes('phone') || c.includes('address') || c.includes('date of birth') ||
        c.includes('credit card') || c.includes('bank') || c.includes('social security') ||
        c.includes('ip address') || c.includes('physical'),
      );

      if (hasPasswordInBreach) {
        hasPasswords = true;
        passwordBreaches.push(breach);
      } else if (hasPiiInBreach) {
        piiBreaches.push(breach);
      } else {
        emailOnlyBreaches.push(breach);
      }

      if (classesLower.some((c: string) => c.includes('phone'))) hasPhoneNumbers = true;
      if (classesLower.some((c: string) => c.includes('physical') || c.includes('address'))) hasPhysicalAddresses = true;
      if (classesLower.some((c: string) => c.includes('date of birth'))) hasDOB = true;
      if (classesLower.some((c: string) => c.includes('credit') || c.includes('bank') || c.includes('financial'))) hasFinancialData = true;
    }

    // Find most recent breach date
    const allDates = breachDetails.map((b) => b.BreachDate).filter(Boolean).sort().reverse();
    const mostRecentBreach = allDates[0] || 'nežinoma';

    // ── Generate findings ────────────────────────────────────────────

    // Critical: Password breaches
    if (passwordBreaches.length > 0) {
      const breachList = passwordBreaches.map((b) => {
        const totalPwned = b.PwnCount ? ` (${b.PwnCount.toLocaleString('lt-LT')} paskyrų)` : '';
        return `• ${b.Title || b.Name} (${b.BreachDate})${totalPwned} — nutekėjo: ${b.DataClasses.join(', ')}`;
      }).join('\n');

      // Count affected accounts in password breaches
      const affectedInPwBreaches = Object.entries(accountBreachMap)
        .filter(([, breaches]) => breaches.some((b) => passwordBreaches.map((pb) => pb.Name).includes(b)))
        .length;

      findings.push({
        module: 'hibp',
        severity: 'critical',
        title_lt: `Nutekėję slaptažodžiai — ${passwordBreaches.length} nutekėjimai, ~${affectedInPwBreaches} paskyrų`,
        description_lt:
          `Jūsų organizacijos (${domain}) darbuotojų el. pašto adresai rasti duomenų nutekėjimuose, kuriuose buvo atskleisti SLAPTAŽODŽIAI. ` +
          `Tai reiškia, kad piktavaliai gali turėti jūsų darbuotojų slaptažodžius ir bandyti juos panaudoti prisijungimui prie jūsų sistemų.\n\n` +
          `Nutekėjimai su slaptažodžiais:\n${breachList}\n\n` +
          `Iš viso paveiktų paskyrų: ~${affectedInPwBreaches} (${domain} domene)\n` +
          `Naujausia nutekėjimo data: ${mostRecentBreach}\n\n` +
          `Verslo poveikis: jei darbuotojai naudojo tuos pačius slaptažodžius keliose sistemose (kas yra labai dažna), ` +
          `piktavaliai gali prisijungti prie jūsų el. pašto, VPN, vidinių sistemų ir duomenų bazių.`,
        recommendation_lt:
          `1. SKUBIAI (per 24 val.): priverskite VISUS darbuotojus pakeisti slaptažodžius.\n` +
          `2. Per 48 val.: įjunkite kelių veiksnių autentifikavimą (MFA) visoms paskyroms.\n` +
          `3. Per 7 dienas: patikrinkite prisijungimų žurnalus dėl neautorizuotos prieigos.\n` +
          `4. Informuokite darbuotojus apie sukčiavimo riziką — jie gali gauti tikslines atakas.\n` +
          `5. Ateityje: naudokite slaptažodžių valdymo sistemą (password manager).`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: {
          domain,
          total_affected_accounts: totalAffectedAccounts,
          password_breach_count: passwordBreaches.length,
          password_breaches: passwordBreaches.map((b) => ({
            name: b.Name,
            title: b.Title,
            date: b.BreachDate,
            pwn_count: b.PwnCount,
            data_classes: b.DataClasses,
            is_verified: b.IsVerified,
            description: b.Description?.slice(0, 300),
          })),
          most_recent_breach: mostRecentBreach,
          affected_accounts_sample: Object.keys(accountBreachMap).slice(0, 10),
        },
      });
    }

    // High: PII breaches (phone, address, DOB, financial)
    if (piiBreaches.length > 0) {
      const breachList = piiBreaches.map((b) =>
        `• ${b.Title || b.Name} (${b.BreachDate}) — nutekėjo: ${b.DataClasses.join(', ')}`
      ).join('\n');

      const piiTypes: string[] = [];
      if (hasPhoneNumbers) piiTypes.push('telefono numeriai');
      if (hasPhysicalAddresses) piiTypes.push('fiziniai adresai');
      if (hasDOB) piiTypes.push('gimimo datos');
      if (hasFinancialData) piiTypes.push('finansiniai duomenys');

      findings.push({
        module: 'hibp',
        severity: 'high',
        title_lt: `Asmens duomenų nutekėjimas — ${piiBreaches.length} nutekėjimai`,
        description_lt:
          `Jūsų organizacijos darbuotojų asmens duomenys rasti šiuose nutekėjimuose:\n${breachList}\n\n` +
          `Nutekėję duomenų tipai: ${piiTypes.join(', ')}.\n` +
          `Šie duomenys gali būti naudojami tikslinėms sukčiavimo atakoms (spear phishing), tapatybės vagystei arba socialinei inžinerijai.`,
        recommendation_lt:
          `1. Informuokite paveiktus darbuotojus apie nutekėjimą.\n` +
          `2. Perspėkite apie galimas tikslines sukčiavimo atakas.\n` +
          `3. Peržiūrėkite el. pašto saugumo nustatymus (DMARC/SPF).\n` +
          `4. Apsvarstykite darbuotojų mokymą apie sukčiavimo atakų atpažinimą.`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: {
          domain,
          pii_breaches: piiBreaches.map((b) => ({
            name: b.Name,
            title: b.Title,
            date: b.BreachDate,
            pwn_count: b.PwnCount,
            data_classes: b.DataClasses,
          })),
          pii_types_exposed: piiTypes,
        },
      });
    }

    // Medium: Email-only breaches
    if (emailOnlyBreaches.length > 0) {
      const breachList = emailOnlyBreaches.map((b) =>
        `• ${b.Title || b.Name} (${b.BreachDate})`
      ).join('\n');

      findings.push({
        module: 'hibp',
        severity: 'medium',
        title_lt: `El. pašto adresai rasti ${emailOnlyBreaches.length} nutekėjimuose`,
        description_lt:
          `Jūsų organizacijos el. pašto adresai rasti šiuose nutekėjimuose:\n${breachList}\n\n` +
          `Nors slaptažodžiai ir asmens duomenys nebuvo tiesiogiai atskleisti, nutekėję el. pašto adresai gali būti naudojami masinėms sukčiavimo atakoms ir spam siuntimui.`,
        recommendation_lt:
          `1. Informuokite darbuotojus apie galimą padidėjusį spam ir sukčiavimo laiškų kiekį.\n` +
          `2. Peržiūrėkite el. pašto filtravimo nustatymus.`,
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: {
          domain,
          email_only_breaches: emailOnlyBreaches.map((b) => ({
            name: b.Name,
            title: b.Title,
            date: b.BreachDate,
          })),
        },
      });
    }

    // Overall summary finding
    if (findings.length > 0) {
      // Add a summary finding with aggregate statistics
      findings.push({
        module: 'hibp',
        severity: 'info',
        title_lt: `Duomenų nutekėjimų suvestinė — ${totalAffectedAccounts} paskyrų, ${breachNames.size} nutekėjimų`,
        description_lt:
          `Bendra statistika domeno ${domain} nutekėjimams:\n` +
          `• Paveiktų paskyrų skaičius: ~${totalAffectedAccounts}\n` +
          `• Unikalių nutekėjimų skaičius: ${breachNames.size}\n` +
          `• Naujausia nutekėjimo data: ${mostRecentBreach}\n` +
          `• Nutekėjusių duomenų tipai: ${Array.from(allDataClasses).join(', ')}\n` +
          `${hasPasswords ? '• ⚠ Slaptažodžiai buvo atskleisti!\n' : ''}` +
          `${hasFinancialData ? '• ⚠ Finansiniai duomenys buvo atskleisti!\n' : ''}`,
        recommendation_lt: 'Žr. aukščiau esančias rekomendacijas pagal kiekvieną nutekėjimo kategoriją.',
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: {
          domain,
          total_accounts: totalAffectedAccounts,
          total_breaches: breachNames.size,
          all_data_classes: Array.from(allDataClasses),
          most_recent_breach: mostRecentBreach,
          has_passwords: hasPasswords,
          has_financial_data: hasFinancialData,
          breach_names: Array.from(breachNames),
        },
      });
    }

    // ── Step 3: Per-email breach check (professional plan) ───────────
    if (options?.emails && options.emails.length > 0) {
      const emailsToCheck = options.emails.slice(0, 20);
      console.log(`[hibp] Checking ${emailsToCheck.length} individual emails`);

      const emailPasswordBreaches: string[] = [];
      const emailPiiBreaches: string[] = [];
      const emailOnlyBreachEmails: string[] = [];

      for (const email of emailsToCheck) {
        try {
          const emailRes = await fetchWithTimeout(
            `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
            { headers },
            10_000,
          );

          if (emailRes.status === 404) {
            // No breaches for this email
            await sleep(1600);
            continue;
          }

          if (!emailRes.ok) {
            await emailRes.text().catch(() => '');
            await sleep(1600);
            continue;
          }

          const emailBreaches = await emailRes.json() as Array<{
            Name: string; Title: string; BreachDate: string;
            DataClasses: string[]; PwnCount: number;
          }>;

          const masked = maskEmail(email);
          const hasPassword = emailBreaches.some((b) =>
            b.DataClasses.some((dc) => dc.toLowerCase().includes('password')),
          );
          const hasPii = emailBreaches.some((b) =>
            b.DataClasses.some((dc) => {
              const lower = dc.toLowerCase();
              return lower.includes('phone') || lower.includes('address') ||
                lower.includes('date of birth') || lower.includes('credit');
            }),
          );

          if (hasPassword) {
            emailPasswordBreaches.push(masked);
          } else if (hasPii) {
            emailPiiBreaches.push(masked);
          } else {
            emailOnlyBreachEmails.push(masked);
          }

          // HIBP rate limit: 1 request per 1.5s
          await sleep(1600);
        } catch {
          await sleep(1600);
          continue;
        }
      }

      // Generate aggregated findings per severity tier
      if (emailPasswordBreaches.length > 0) {
        findings.push({
          module: 'hibp',
          severity: 'critical',
          title_lt: `Individualūs el. paštai su nutekėjusiais slaptažodžiais — ${emailPasswordBreaches.length} paskyros`,
          description_lt:
            `Šie el. pašto adresai rasti duomenų nutekėjimuose, kuriuose buvo atskleisti slaptažodžiai:\n` +
            emailPasswordBreaches.map((e) => `• ${e}`).join('\n') + '\n\n' +
            `Piktavaliai gali bandyti prisijungti prie jūsų sistemų naudodami nutekėjusius slaptažodžius.`,
          recommendation_lt:
            `1. SKUBIAI: priverskite šiuos vartotojus pakeisti slaptažodžius.\n` +
            `2. Įjunkite kelių veiksnių autentifikavimą (MFA).\n` +
            `3. Patikrinkite prisijungimų žurnalus.`,
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: {
            domain,
            email_count: emailPasswordBreaches.length,
            masked_emails: emailPasswordBreaches,
            breach_type: 'password',
          },
        });
      }

      if (emailPiiBreaches.length > 0) {
        findings.push({
          module: 'hibp',
          severity: 'high',
          title_lt: `Individualūs el. paštai su nutekėjusiais asmens duomenimis — ${emailPiiBreaches.length} paskyros`,
          description_lt:
            `Šie el. pašto adresai rasti nutekėjimuose su asmens duomenimis (telefono nr., adresai, gimimo datos):\n` +
            emailPiiBreaches.map((e) => `• ${e}`).join('\n'),
          recommendation_lt:
            `1. Informuokite paveiktus darbuotojus.\n` +
            `2. Perspėkite apie galimas tikslines sukčiavimo atakas.`,
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: {
            domain,
            email_count: emailPiiBreaches.length,
            masked_emails: emailPiiBreaches,
            breach_type: 'pii',
          },
        });
      }

      if (emailOnlyBreachEmails.length > 0) {
        findings.push({
          module: 'hibp',
          severity: 'medium',
          title_lt: `Individualūs el. paštai rasti nutekėjimuose — ${emailOnlyBreachEmails.length} paskyros`,
          description_lt:
            `Šie el. pašto adresai rasti duomenų nutekėjimuose (be slaptažodžių):\n` +
            emailOnlyBreachEmails.map((e) => `• ${e}`).join('\n'),
          recommendation_lt: 'Informuokite darbuotojus apie galimą padidėjusį spam kiekį.',
          nis2_article: '11 str. 2 d. 9 p.',
          evidence: {
            domain,
            email_count: emailOnlyBreachEmails.length,
            masked_emails: emailOnlyBreachEmails,
            breach_type: 'email_only',
          },
        });
      }
    }

    return { module: 'hibp', success: true, findings };
  } catch (err) {
    return {
      module: 'hibp',
      success: false,
      findings: [],
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
