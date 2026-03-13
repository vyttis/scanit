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
  'Būk konkretus: ne "atnaujinkite programinę įrangą" o "kreipkitės į IT administratorių su šiuo sąrašu ir paprašykite patvirtinimo kad visi atnaujinimai įdiegti per 30 dienų".';

function getAnthropicClient(): Anthropic {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY environment variable is not set');
  }
  return new Anthropic({ apiKey, timeout: 60000 });
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

  const prompt =
    `Sugeneruok detalų aprašymą ir rekomendaciją šiam kibernetinio saugumo radiniui:\n\n` +
    `Modulis: ${finding.module}\n` +
    `Sunkumas: ${finding.severity}\n` +
    `Pavadinimas: ${finding.title_lt}\n` +
    `Įrodymai (JSON): ${JSON.stringify(finding.evidence ?? {})}\n\n` +
    `Atsakyk JSON formatu:\n` +
    `{"description_lt": "...", "recommendation_lt": "..."}\n\n` +
    `description_lt turi turėti šias dalis (naudok \\n\\n tarp dalių):\n` +
    `- KAS TAI: aiškus paaiškinimas paprastais žodžiais (1-2 sakiniai)\n` +
    `- KODĖL TAI PAVOJINGA: konkretus scenarijus kas galėtų nutikti (2-3 sakiniai)\n` +
    `- VERSLO POVEIKIS: duomenų praradimas, finansinė žala, reputacijos žala, reguliacinės baudos (1-2 sakiniai)\n\n` +
    `recommendation_lt turi turėti konkrečius sunumeruotus žingsnius (1. ... 2. ... 3. ...), ` +
    `su terminais ir atsakingais asmenimis. Ne bendri patarimai, o konkretūs veiksmai.`;

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
