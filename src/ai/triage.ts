import type { Finding } from '../core/finding.js';
import { severityRank } from '../core/finding.js';
import type { AiConfig } from '../core/config.js';
import { fixtureExplain, fixtureTriage } from './fixtures.js';
import { asExplanation, asTriage } from './parse.js';
import type { AiClient } from './provider.js';

function cap(findings: readonly Finding[], max: number): Finding[] {
  return [...findings]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, max);
}

/**
 * Label findings. Fixture mode uses recorded labels. Live mode uses the
 * model's JSON. Never removes a finding — high/critical stay even if the
 * model says likely-false-positive.
 */
export async function applyTriage(
  findings: Finding[],
  client: AiClient,
  config: AiConfig,
  snippets: Record<string, string>,
): Promise<Finding[]> {
  const budget = cap(findings, config.maxFindings);
  for (const finding of budget) {
    const snippet = snippets[finding.file ?? ''] ?? finding.snippet ?? finding.message;
    const res = await client.complete({
      mode: 'triage',
      prompt: `${finding.ruleId}\n${snippet}`,
    });
    if (res === null) {continue;}
    if (client.useFixtures) {
      const label = fixtureTriage(finding.ruleId);
      finding.aiVerdict = label.verdict;
      finding.aiReasoning = label.reasoning;
      finding.exploitScenario = label.exploitScenario;
      continue;
    }
    const live = asTriage(res.json);
    if (live === undefined) {continue;}
    finding.aiVerdict = live.verdict;
    finding.aiReasoning = live.reasoning;
    finding.exploitScenario = live.exploitScenario;
  }
  return findings;
}

export async function applyExplain(
  findings: Finding[],
  client: AiClient,
  config: AiConfig,
  snippets: Record<string, string>,
): Promise<Finding[]> {
  const budget = cap(findings, config.maxFindings);
  for (const finding of budget) {
    const snippet = snippets[finding.file ?? ''] ?? finding.snippet ?? finding.message;
    const res = await client.complete({
      mode: 'explain',
      prompt: `${finding.ruleId}\n${snippet}`,
    });
    if (res === null) {continue;}
    if (client.useFixtures) {
      finding.explanation = fixtureExplain(finding.ruleId);
      continue;
    }
    const text = asExplanation(res.json);
    if (text !== undefined) {finding.explanation = text;}
    delete finding.aiVerdict;
    delete finding.exploitScenario;
    delete finding.aiReasoning;
  }
  return findings;
}
