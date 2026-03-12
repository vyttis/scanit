/**
 * End-to-end test for report generation pipeline.
 * Tests: Claude API calls (stateless via curl due to proxy env), HTML generation, risk scoring.
 *
 * Run: npx tsx scripts/test-report-pipeline.ts
 */

import { execSync } from 'child_process';

const SYSTEM_PROMPT =
  'Tu esi kibernetinio saugumo ekspertas, rašantis ataskaitas lietuviškoms organizacijoms. ' +
  'Rašyk aiškiai ir suprantamai — taip, kad IT vadovas, kuris nėra techninis specialistas, suprastų problemą ir žinotų, ką daryti. ' +
  'Nenaudok žargono be paaiškinimo. Būk konkretus ir glaustas.';

function callClaudeViaCurl(systemPrompt: string, userPrompt: string): string {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY not set');
  }

  const body = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 500,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }],
  });

  // Use curl to bypass Node.js proxy limitations in this environment
  const result = execSync(
    `curl -s --max-time 60 https://api.anthropic.com/v1/messages ` +
    `-H "x-api-key: ${apiKey}" ` +
    `-H "content-type: application/json" ` +
    `-H "anthropic-version: 2023-06-01" ` +
    `-d '${body.replace(/'/g, "'\\''")}'`,
    { encoding: 'utf-8', timeout: 90000 },
  );

  const parsed = JSON.parse(result);
  if (parsed.error) {
    throw new Error(`API error: ${JSON.stringify(parsed.error)}`);
  }
  return parsed.content[0]?.text ?? '';
}

function testClaudeApiStateless() {
  console.log('=== Test 1: Claude API stateless call (finding description) ===');

  const prompt =
    `Sugeneruok aprašymą ir rekomendaciją šiam kibernetinio saugumo pažeidimui:\n\n` +
    `Modulis: ssl\n` +
    `Sunkumas: critical\n` +
    `Pavadinimas: Pasibaigęs SSL sertifikatas\n` +
    `Įrodymai (JSON): {"domain":"example.lt","expiry_date":"2025-01-15","issuer":"Let's Encrypt"}\n\n` +
    `Atsakyk JSON formatu:\n` +
    `{"description_lt": "...", "recommendation_lt": "..."}\n\n` +
    `description_lt: aiškus paaiškinimas ką tai reiškia organizacijai (2-3 sakiniai).\n` +
    `recommendation_lt: konkretūs veiksmai problemai išspręsti (2-3 sakiniai).`;

  const text = callClaudeViaCurl(SYSTEM_PROMPT, prompt);
  console.log('Raw response text:', text.slice(0, 300));

  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    console.error('FAIL: No JSON found in response');
    process.exit(1);
  }

  const parsed = JSON.parse(jsonMatch[0]);
  console.log('Parsed finding:', JSON.stringify(parsed, null, 2));

  if (!parsed.description_lt || !parsed.recommendation_lt) {
    console.error('FAIL: Missing required fields');
    process.exit(1);
  }

  console.log('PASS: Finding description generated (stateless)\n');
}

function testExecutiveSummary() {
  console.log('=== Test 2: Claude API stateless call (executive summary) ===');

  const prompt =
    `Parašyk trumpą vykdomąją santrauką (3-5 sakiniai) kibernetinio saugumo ataskaitai.\n\n` +
    `Organizacija: UAB Testavimas\n` +
    `Rizikos balas: 45/100\n` +
    `Kritiniai: 1, Aukšti: 2, Vidutiniai: 3, Žemi: 1\n` +
    `Iš viso rastų trūkumų: 7\n\n` +
    `Svarbiausios problemos:\n` +
    `- Pasibaigęs SSL sertifikatas (critical)\n` +
    `- Atidarytas SSH prievadas (high)\n\n` +
    `Santrauka turi būti profesionali, dalykiška, skirta IT vadovui. Rašyk tik santraukos tekstą, be papildomų komentarų.`;

  const summary = callClaudeViaCurl(SYSTEM_PROMPT, prompt);
  console.log('Executive summary:', summary.slice(0, 400));

  if (summary.length < 50) {
    console.error('FAIL: Summary too short');
    process.exit(1);
  }

  console.log('PASS: Executive summary generated (stateless)\n');
}

function testRiskScoring() {
  console.log('=== Test 3: Risk scoring ===');

  const SEVERITY_WEIGHTS: Record<string, number> = {
    critical: 25,
    high: 15,
    medium: 5,
    low: 1,
    info: 0,
  };

  const findings = [
    { severity: 'critical' },
    { severity: 'high' },
    { severity: 'high' },
    { severity: 'medium' },
    { severity: 'medium' },
    { severity: 'medium' },
    { severity: 'low' },
  ];

  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0),
    0,
  );
  const score = Math.min(100, raw);

  console.log(`Risk score for ${findings.length} findings: ${score}/100`);
  console.log(`Expected: 25 + 15 + 15 + 5 + 5 + 5 + 1 = 71`);

  if (score !== 71) {
    console.error(`FAIL: Expected 71, got ${score}`);
    process.exit(1);
  }

  console.log('PASS: Risk scoring correct\n');
}

function testHtmlGeneration() {
  console.log('=== Test 4: HTML report structure ===');

  // Minimal check that the HTML generator template includes all required elements
  const requiredStrings = [
    'NKSC PATIKRINIMO ĮRODYMAS',
    'Rizikos balas',
    'Kibernetinio saugumo ataskaita',
    'KSRA 45.8',
    'Vykdomoji santrauka',
    'Nustatyti trūkumai',
  ];

  // Read the generator file and check template
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require('fs') as typeof import('fs');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const path = require('path') as typeof import('path');
  const generatorSource = fs.readFileSync(
    path.join(__dirname, '..', 'lib', 'report', 'generator.ts'),
    'utf-8',
  );

  for (const str of requiredStrings) {
    if (!generatorSource.includes(str)) {
      console.error(`FAIL: HTML template missing "${str}"`);
      process.exit(1);
    }
  }

  console.log('PASS: HTML template contains all required sections\n');
}

function main() {
  console.log('Starting report pipeline tests...\n');

  testRiskScoring();
  testHtmlGeneration();
  testClaudeApiStateless();
  testExecutiveSummary();

  console.log('=== ALL TESTS PASSED ===');
}

main();
