import { describe, expect, it } from 'vitest';

import { applyExplain, applyTriage } from '../../../src/ai/triage.js';
import { asTriage, extractJson } from '../../../src/ai/parse.js';
import type { AiClient } from '../../../src/ai/provider.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';

function finding(): Finding {
  return {
    id: makeFindingId('SAST-SQLI-001', 'a.js', 'q'),
    ruleId: 'SAST-SQLI-001',
    module: 'sast',
    title: 'SQL injection',
    severity: 'high',
    confidence: 'high',
    file: 'a.js',
    message: 'concatenated query',
    remediation: 'parameterize',
  };
}

function liveClient(json: unknown): AiClient {
  return {
    enabled: true,
    useFixtures: false,
    networkCalls: 1,
    spentUsd: 0,
    complete: () => Promise.resolve({ json, costUsd: 0, cached: false, redactedPrompt: '' }),
  };
}

describe('live AI path applies the model JSON (harden-4)', () => {
  it('uses the live triage verdict instead of the recorded fixture label', async () => {
    const findings = [finding()];
    await applyTriage(
      findings,
      liveClient({
        verdict: 'likely-false-positive',
        reasoning: 'from the live model',
        exploitScenario: 'none',
      }),
      { enabled: true, maxCostUsd: 1, maxFindings: 50 },
      {},
    );
    expect(findings[0]?.aiVerdict).toBe('likely-false-positive');
    expect(findings[0]?.aiReasoning).toBe('from the live model');
    expect(findings[0]?.severity).toBe('high');
  });

  it('uses the live explanation text', async () => {
    const findings = [finding()];
    await applyExplain(
      findings,
      liveClient({ explanation: 'A live model wrote this sentence.' }),
      { enabled: true, maxCostUsd: 1, maxFindings: 50 },
      {},
    );
    expect(findings[0]?.explanation).toBe('A live model wrote this sentence.');
  });

  it('extracts JSON from an Ollama-style fenced reply', () => {
    const parsed = extractJson('Sure.\n```json\n{"verdict":"needs-review","reasoning":"x","exploitScenario":"y"}\n```');
    expect(asTriage(parsed)?.verdict).toBe('needs-review');
  });
});
