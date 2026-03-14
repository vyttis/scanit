import type { ScannerResult, ScannerFinding } from './types';
import { fetchWithTimeout } from './types';

/**
 * HaveIBeenPwned scanner — checks breached emails by domain.
 * Severity: Critical if passwords exposed, High if emails in breach.
 * KSĮ: Art. 11(2)(i) — prieigos valdymas ir MFA
 *
 * @param options.emails - Specific employee emails to check (professional plan)
 */
export async function scanHibp(domain: string): Promise<ScannerResult> {
  const apiKey = process.env.HIBP_API_KEY?.trim();
  if (!apiKey) {
    return { module: 'hibp', success: false, findings: [], error: 'HIBP_API_KEY not configured' };
  }

  try {
    const url = `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`;
    console.log(`[hibp] GET ${url} (key length: ${apiKey.length})`);
    const res = await fetchWithTimeout(
      url,
      {
        headers: {
          'hibp-api-key': apiKey,
          'user-agent': 'scanit.lt-platform',
        },
      },
      15_000,
    );

    console.log(`[hibp] Response: ${res.status}`);

    if (res.status === 404) {
      return {
        module: 'hibp',
        success: true,
        findings: [{
          module: 'hibp',
          severity: 'info',
          title_lt: 'Duomenų nutekėjimų nerasta',
          description_lt: `Domeno ${domain} el. pašto adresai nebuvo rasti žinomose duomenų nutekėjimo bazėse. Tai yra teigiamas ženklas.`,
          recommendation_lt: 'Tęskite periodinį stebėjimą ir naudokite stiprius, unikalius slaptažodžius su kelių veiksnių autentifikavimu.',
          nis2_article: null,
          evidence: { domain, breaches_found: 0 },
        }],
      };
    }

    if (!res.ok) {
      return { module: 'hibp', success: false, findings: [], error: `HIBP API returned: ${res.status}` };
    }

    const breaches = await res.json();
    const findings: ScannerFinding[] = [];

    if (!Array.isArray(breaches) || breaches.length === 0) {
      findings.push({
        module: 'hibp',
        severity: 'info',
        title_lt: 'Duomenų nutekėjimų nerasta',
        description_lt: `Domeno ${domain} el. pašto adresai nebuvo rasti žinomose duomenų nutekėjimo bazėse.`,
        recommendation_lt: 'Tęskite periodinį stebėjimą.',
        nis2_article: null,
        evidence: { domain, breaches_found: 0 },
      });
      return { module: 'hibp', success: true, findings };
    }

    // Check for password-containing breaches
    const passwordBreaches = breaches.filter((b: { DataClasses: string[] }) =>
      b.DataClasses?.some((dc: string) => dc.toLowerCase().includes('password')),
    );

    const otherBreaches = breaches.filter((b: { DataClasses: string[] }) =>
      !b.DataClasses?.some((dc: string) => dc.toLowerCase().includes('password')),
    );

    if (passwordBreaches.length > 0) {
      const breachNames = passwordBreaches.map((b: { Name: string }) => b.Name).join(', ');
      findings.push({
        module: 'hibp',
        severity: 'critical',
        title_lt: `Nutekėję slaptažodžiai — ${passwordBreaches.length} nutekėjimai su slaptažodžiais`,
        description_lt: `Domeno ${domain} el. pašto adresai rasti duomenų nutekėjimuose, kuriuose buvo atskleisti slaptažodžiai: ${breachNames}. Jei darbuotojai naudojo tuos pačius slaptažodžius kitur — piktavaliai gali bandyti prisijungti prie jūsų sistemų.`,
        recommendation_lt: 'Nedelsiant priverskite visus darbuotojus pakeisti slaptažodžius. Įjunkite kelių veiksnių autentifikavimą (MFA) visoms paskyroms. Patikrinkite, ar nėra neautorizuotų prisijungimų.',
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: {
          domain,
          password_breaches: passwordBreaches.map((b: { Name: string; BreachDate: string; PwnCount: number; DataClasses: string[] }) => ({
            name: b.Name, date: b.BreachDate, pwn_count: b.PwnCount, data_classes: b.DataClasses,
          })),
        },
      });
    }

    if (otherBreaches.length > 0) {
      const breachNames = otherBreaches.map((b: { Name: string }) => b.Name).join(', ');
      findings.push({
        module: 'hibp',
        severity: 'high',
        title_lt: `El. pašto adresai rasti ${otherBreaches.length} duomenų nutekėjimuose`,
        description_lt: `Domeno ${domain} el. pašto adresai rasti šiuose duomenų nutekėjimuose: ${breachNames}. Nors slaptažodžiai nebuvo tiesiogiai atskleisti, nutekėję duomenys (el. pašto adresai, vardai, IP adresai) gali būti naudojami tikslinėms sukčiavimo atakoms.`,
        recommendation_lt: 'Informuokite darbuotojus apie galimą sukčiavimo riziką. Peržiūrėkite el. pašto saugumo nustatymus ir DMARC/SPF konfigūraciją.',
        nis2_article: '11 str. 2 d. 9 p.',
        evidence: {
          domain,
          other_breaches: otherBreaches.map((b: { Name: string; BreachDate: string; PwnCount: number; DataClasses: string[] }) => ({
            name: b.Name, date: b.BreachDate, pwn_count: b.PwnCount, data_classes: b.DataClasses,
          })),
        },
      });
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
