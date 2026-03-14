import Anthropic from '@anthropic-ai/sdk';
import type { Finding } from '@/types/database';

const SYSTEM_PROMPT =
  'Tu esi kibernetinio saugumo ekspertas, rašantis ataskaitas lietuviškų organizacijų vadovams ir IT vadybininkams — ne technikams. ' +
  'Kiekvienam radiniui privalai pateikti: ' +
  '1. Ką tai reiškia paprastais žodžiais — be techninių terminų ar su jų paaiškinimu. ' +
  '2. Kodėl tai pavojinga — konkretus scenarijus kas galėtų nutikti jei problema nebus išspręsta. ' +
  '3. Koks verslo poveikis — duomenų praradimas, finansinė žala, reputacijos žala, reguliacinės baudos. ' +
  '4. Kaip tai palyginti su KSĮ reikalavimais — kokia konkreti teisinė rizika. ' +
  '5. Ką reikia padaryti — konkretūs žingsniai, ne bendri patarimai. ' +
  'Rašyk taip, tarsi aiškintum savo direktoriui, kuris nėra techninis specialistas, bet supranta verslo rizikas. ' +
  'Vengk žargono. Jei naudoji techninius terminus — visada paaiškink. ' +
  'Būk konkretus: ne "atnaujinkite programinę įrangą" o "kreipkitės į IT administratorių su šiuo sąrašu ir paprašykite patvirtinimo kad visi atnaujinimai įdiegti per 30 dienų". ' +
  '\n\nKai evidence JSON turi detalius duomenis, naudok juos konkrečiai:\n' +
  '- CVE pažeidžiamumams: nurodyk CVSS balą, paveiktą programinę įrangą ir versiją, ar žinomas exploit (pvz. "Apache 2.2.15 turi kritinį pažeidžiamumą CVE-2021-44228 su CVSS 10.0 — atakos įrankiai jau egzistuoja").\n' +
  '- Duomenų nutekėjimams: nurodyk kokie duomenys nutekėjo, kiek paskyrų paveikta, kada įvyko (pvz. "2023 m. LinkedIn nutekėjime atskleisti 500 jūsų darbuotojų el. paštai ir slaptažodžiai").\n' +
  '- SSL/TLS: nurodyk konkrečius pažeidžiamus protokolus ir šifrus lietuviškai (pvz. "serveris vis dar palaiko TLS 1.0 — tai 2008 m. protokolas su žinomomis atakomis BEAST ir POODLE").\n' +
  '- El. pašto saugumui: nurodyk konkrečią SPF/DKIM/DMARC konfigūracijos problemą (pvz. "DMARC politika none — suklastoti laiškai bus pristatyti, o ne blokuojami").\n' +
  '- Juodiesiems sąrašams: nurodyk kuriuose blacklist ir kodėl (pvz. "IP 1.2.3.4 rastas Spamhaus zen.spamhaus.org sąraše — tai reiškia, kad jūsų laiškai bus blokuojami daugelio gavėjų").\n' +
  '- IP piktnaudžiavimui: nurodyk piktnaudžiavimo kategorijas (pvz. "IP adresas praneštas dėl SSH brute-force ir port scan atakų").\n' +
  '- Subdomenams: pateik konkrečius kabančius subdomenis ir paaiškink takeover riziką.\n' +
  '- WHOIS: nurodyk registracijos pabaigos datą ir registratorių.\n' +
  '- VirusTotal: nurodyk kurie saugumo tiekėjai pažymėjo domeną, ar rasta komunikuojančių kenkėjiškų programų.';

function getAnthropicClient(): Anthropic {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY environment variable is not set');
  }
  return new Anthropic({ apiKey, timeout: 60000 });
}

/**
 * Generate module-specific context hints for the Claude prompt
 * so it knows which evidence fields to highlight in the Lithuanian text.
 */
function getModuleHints(module: string, evidence: Record<string, unknown>): string {
  switch (module) {
    case 'shodan':
      return (
        'Šis radinys iš Shodan — tinklų saugumo skenerio. ' +
        (evidence.critical_cves ? `Svarbu: paminėk konkrečius CVE numerius, jų CVSS balus ir paveiktą programinę įrangą. Jei yra ŽINOMAS IŠNAUDOJIMAS — pabrėžk tai. ` : '') +
        (evidence.exposed_sensitive ? `Paminėk konkrečius atvirų prievadų numerius, paslaugų pavadinimus ir programinės įrangos versijas. ` : '') +
        (evidence.outdated_software ? `Paminėk konkrečias pasenusias programas ir jų versijas, paaiškink kodėl senos versijos pavojingos. ` : '') +
        (evidence.os_detection ? `Aptikta OS: ${evidence.os_detection}. ` : '')
      );
    case 'hibp':
      return (
        'Šis radinys iš HaveIBeenPwned — duomenų nutekėjimų duomenų bazės. ' +
        (evidence.password_breaches ? `KRITIŠKAI SVARBU: nutekėjo SLAPTAŽODŽIAI. Paminėk konkrečius nutekėjimo pavadinimus, datas, kiek paskyrų paveikta ir kokio tipo duomenys nutekėjo. ` : '') +
        (evidence.total_accounts ? `Paminėk bendrą paveiktų paskyrų skaičių. ` : '') +
        (evidence.most_recent_breach ? `Naujausias nutekėjimas: ${evidence.most_recent_breach}. ` : '') +
        `Paaiškink slaptažodžių pakartotinio naudojimo riziką (credential stuffing).`
      );
    case 'ssl':
      return (
        'Šis radinys iš SSL Labs — SSL/TLS sertifikatų ir šifravimo tikrinimo. ' +
        (evidence.protocols ? `Paminėk konkrečius palaikomus protokolus lietuviškai (pvz. "TLS 1.0 — pasenęs nuo 2020 m."). ` : '') +
        (evidence.weak_ciphers ? `Paminėk silpnus šifrus ir kodėl jie pavojingi. ` : '') +
        (evidence.heartbleed || evidence.poodle || evidence.drown ? `KRITIŠKAI SVARBU: rastos žinomos atakos (Heartbleed/POODLE/DROWN). Paaiškink kiekvieną ataką paprastais žodžiais. ` : '') +
        (evidence.days_until_expiry !== undefined ? `Paminėk tikslų dienų skaičių iki sertifikato pabaigos. ` : '')
      );
    case 'mxtoolbox':
      return (
        'Šis radinys iš el. pašto saugumo tikrinimo (SPF/DKIM/DMARC/blacklist). ' +
        (evidence.spf ? `Paminėk konkrečią SPF konfigūracijos problemą. ` : '') +
        (evidence.dmarc ? `Paminėk DMARC politiką ir ką ji reiškia praktiškai. ` : '') +
        (evidence.blacklisted_entries ? `SVARBU: IP rastas blacklist sąrašuose. Paminėk kuriuose ir ką tai reiškia el. laiškų pristatymui. ` : '') +
        `Paaiškink ką reiškia suklastotas el. laiškas ir kaip tai veikia verslą.`
      );
    case 'securitytrails':
      return (
        'Šis radinys iš SecurityTrails — subdomenų ir DNS žvalgybos. ' +
        (evidence.dangling_subdomains ? `Paminėk konkrečius kabančius subdomenis ir paaiškink subdomain takeover ataką paprastais žodžiais. ` : '') +
        (evidence.expiry_date ? `Paminėk domeno registracijos pabaigos datą. ` : '') +
        (evidence.dns_type === 'ns' ? `SVARBU: NS pakeitimas gali reikšti domeno užgrobimą. ` : '') +
        (evidence.privacy_protection === false ? `Paminėk WHOIS privatumo trūkumą ir kokią informaciją mato visi. ` : '')
      );
    case 'virustotal':
      return (
        'Šis radinys iš VirusTotal — domeno ir IP reputacijos. ' +
        (evidence.communicating_files ? `KRITIŠKAI SVARBU: rastos kenkėjiškos programos, kurios komunikuoja su domenu (C2 centras). ` : '') +
        (evidence.downloaded_files ? `Domenas platina kenkėjiškus failus. ` : '') +
        (evidence.flagged_by ? `Paminėk konkrečius saugumo tiekėjus, kurie pažymėjo domeną. ` : '') +
        `Paaiškink ką reiškia domeno reputacija ir kaip tai veikia verslą.`
      );
    case 'abuseipdb':
      return (
        'Šis radinys iš AbuseIPDB — IP piktnaudžiavimo duomenų bazės. ' +
        (evidence.top_categories ? `Paminėk konkrečias piktnaudžiavimo kategorijas (pvz. brute-force, port scan). ` : '') +
        (evidence.abuse_confidence ? `Piktnaudžiavimo pasitikėjimo balas: ${evidence.abuse_confidence}%. ` : '') +
        `Paaiškink ką reiškia IP piktnaudžiavimo pranešimai ir ar serveris gali būti pažeistas.`
      );
    case 'urlscan':
      return (
        'Šis radinys iš URLScan.io — svetainių skenavimo. ' +
        (evidence.malicious_lookalikes ? `KRITIŠKAI SVARBU: rasti kenkėjiški panašūs domenai (phishing). Paminėk juos konkrečiai. ` : '') +
        (evidence.final_domain ? `Svetainė peradresuoja į ${evidence.final_domain}. ` : '') +
        `Paaiškink phishing ir typosquatting grėsmes paprastais žodžiais.`
      );
    default:
      return '';
  }
}

/**
 * Generate a Lithuanian-language description for a single finding.
 * Returns structured sections: what it is, why dangerous, business impact, remediation.
 */
export async function generateFindingDescription(finding: {
  module: string;
  severity: string;
  title_lt: string;
  evidence: Record<string, unknown> | null;
}): Promise<{ description_lt: string; recommendation_lt: string }> {
  const anthropic = getAnthropicClient();

  // Build module-specific context hints
  const evidence = finding.evidence ?? {};
  const moduleHints = getModuleHints(finding.module, evidence);

  const prompt =
    `Sugeneruok detalų aprašymą ir rekomendaciją šiam kibernetinio saugumo radiniui:\n\n` +
    `Modulis: ${finding.module}\n` +
    `Sunkumas: ${finding.severity}\n` +
    `Pavadinimas: ${finding.title_lt}\n` +
    `Įrodymai (JSON): ${JSON.stringify(evidence)}\n\n` +
    `${moduleHints}\n\n` +
    `Atsakyk JSON formatu:\n` +
    `{"description_lt": "...", "recommendation_lt": "..."}\n\n` +
    `description_lt turi turėti šias dalis (naudok \\n\\n tarp dalių):\n` +
    `- KAS TAI: aiškus paaiškinimas paprastais žodžiais, naudojant konkrečius duomenis iš evidence (1-2 sakiniai)\n` +
    `- KODĖL TAI PAVOJINGA: konkretus scenarijus su evidence duomenimis — pvz., CVE numeriai, nutekėję duomenys, pažeidžiami protokolai (2-3 sakiniai)\n` +
    `- VERSLO POVEIKIS: duomenų praradimas, finansinė žala, reputacijos žala, KSĮ baudos (1-2 sakiniai)\n\n` +
    `recommendation_lt turi turėti konkrečius sunumeruotus žingsnius (1. ... 2. ... 3. ...), ` +
    `su terminais ir atsakingais asmenimis. Naudok konkrečius duomenis iš evidence (pvz. CVE ID, IP adresus, domeno vardus).`;

  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 800,
    temperature: 0.3,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = response.content[0].type === 'text' ? response.content[0].text : '';

  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON found in response');
    const parsed = JSON.parse(jsonMatch[0]);
    return {
      description_lt: parsed.description_lt || finding.title_lt,
      recommendation_lt: parsed.recommendation_lt || 'Kreipkitės į IT specialistą.',
    };
  } catch {
    return {
      description_lt: text.slice(0, 800),
      recommendation_lt: 'Kreipkitės į IT specialistą dėl šio pažeidimo šalinimo.',
    };
  }
}

/**
 * Generate the executive summary paragraph for page 1 of the report.
 * Fully stateless — one call per report.
 */
export async function generateExecutiveSummary(
  orgName: string,
  findings: Finding[],
  riskScore: number,
): Promise<string> {
  const anthropic = getAnthropicClient();

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;

  const topFindings = findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 3)
    .map((f) => `- ${f.title_lt} (${f.severity})`)
    .join('\n');

  const prompt =
    `Parašyk trumpą vykdomąją santrauką (4-6 sakiniai) kibernetinio saugumo ataskaitai.\n\n` +
    `Organizacija: ${orgName}\n` +
    `Rizikos balas: ${riskScore}/100\n` +
    `Kritiniai: ${criticalCount}, Aukšti: ${highCount}, Vidutiniai: ${mediumCount}, Žemi: ${lowCount}\n` +
    `Iš viso rastų trūkumų: ${findings.length}\n\n` +
    `Svarbiausios problemos:\n${topFindings || 'Kritinių ar aukšto lygio pažeidimų nerasta.'}\n\n` +
    `Santrauka turi:\n` +
    `- Pradėti nuo bendro saugumo būklės vertinimo\n` +
    `- Pabrėžti svarbiausias problemas paprastais žodžiais\n` +
    `- Nurodyti verslo rizikas (baudos, duomenų praradimas, reputacija)\n` +
    `- Baigti konkrečiu kvietimu veikti su terminais\n\n` +
    `Rašyk profesionaliai, dalykiškai, skirta IT vadovui ir direktoriui. Tik santraukos tekstas, be papildomų komentarų.`;

  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 600,
    temperature: 0.3,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: prompt }],
  });

  return response.content[0].type === 'text'
    ? response.content[0].text
    : 'Vykdomoji santrauka negalėjo būti sugeneruota.';
}
