import Anthropic from '@anthropic-ai/sdk';
import type { Finding } from '@/types/database';

const SYSTEM_PROMPT =
  'Tu esi kibernetinio saugumo ekspertas, rašantis ataskaitas lietuviškoms organizacijoms. ' +
  'Rašyk aiškiai ir suprantamai — taip, kad IT vadovas, kuris nėra techninis specialistas, suprastų problemą ir žinotų, ką daryti. ' +
  'Nenaudok žargono be paaiškinimo. Būk konkretus ir glaustas.';

function getAnthropicClient(): Anthropic {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY environment variable is not set');
  }
  return new Anthropic({ apiKey, timeout: 60000 });
}

/**
 * Generate a Lithuanian-language description for a single finding.
 * Each call is fully stateless — no accumulated history.
 */
export async function generateFindingDescription(finding: {
  module: string;
  severity: string;
  title_lt: string;
  evidence: Record<string, unknown> | null;
}): Promise<{ description_lt: string; recommendation_lt: string }> {
  const anthropic = getAnthropicClient();

  const prompt =
    `Sugeneruok aprašymą ir rekomendaciją šiam kibernetinio saugumo pažeidimui:\n\n` +
    `Modulis: ${finding.module}\n` +
    `Sunkumas: ${finding.severity}\n` +
    `Pavadinimas: ${finding.title_lt}\n` +
    `Įrodymai (JSON): ${JSON.stringify(finding.evidence ?? {})}\n\n` +
    `Atsakyk JSON formatu:\n` +
    `{"description_lt": "...", "recommendation_lt": "..."}\n\n` +
    `description_lt: aiškus paaiškinimas ką tai reiškia organizacijai (2-3 sakiniai).\n` +
    `recommendation_lt: konkretūs veiksmai problemai išspręsti (2-3 sakiniai).`;

  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 500,
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
      description_lt: text.slice(0, 500),
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
    `Parašyk trumpą vykdomąją santrauką (3-5 sakiniai) kibernetinio saugumo ataskaitai.\n\n` +
    `Organizacija: ${orgName}\n` +
    `Rizikos balas: ${riskScore}/100\n` +
    `Kritiniai: ${criticalCount}, Aukšti: ${highCount}, Vidutiniai: ${mediumCount}, Žemi: ${lowCount}\n` +
    `Iš viso rastų trūkumų: ${findings.length}\n\n` +
    `Svarbiausios problemos:\n${topFindings || 'Kritinių ar aukšto lygio pažeidimų nerasta.'}\n\n` +
    `Santrauka turi būti profesionali, dalykiška, skirta IT vadovui. Rašyk tik santraukos tekstą, be papildomų komentarų.`;

  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 500,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: prompt }],
  });

  return response.content[0].type === 'text'
    ? response.content[0].text
    : 'Vykdomoji santrauka negalėjo būti sugeneruota.';
}
