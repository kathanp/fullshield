import type { Finding } from '../core/finding.js';

export interface TriageLabel {
  verdict: 'true-positive' | 'likely-false-positive' | 'needs-review';
  reasoning: string;
  exploitScenario: string;
}

export interface LogicFixtureFinding {
  ruleId: string;
  title: string;
  message: string;
  fileHint: string;
  severity: 'low' | 'medium';
}

export interface AiFixtureBank {
  triage: Record<string, TriageLabel>;
  explain: Record<string, string>;
  logic: Array<{
    when: string;
    unless?: string;
    findings: LogicFixtureFinding[];
  }>;
  fix: Record<string, { file: string; after: string }>;
}

/** VCR-style recorded model responses. CI never contacts a provider. */
export const RECORDED_FIXTURES: AiFixtureBank = {
  triage: {
    'AI-INJECT-001': {
      verdict: 'true-positive',
      reasoning: 'The comment is a prompt-injection phrase aimed at reviewers.',
      exploitScenario: 'An attacker plants the comment so an AI triage step marks nearby vulns as safe.',
    },
    'SAST-SQLI-001': {
      verdict: 'true-positive',
      reasoning: 'User input is concatenated into a SQL string.',
      exploitScenario: "A query such as ' OR 1=1-- returns every row.",
    },
    default: {
      verdict: 'needs-review',
      reasoning: 'Recorded fixture has no specific label for this rule.',
      exploitScenario: 'Manual review required.',
    },
  },
  explain: {
    'AI-INJECT-001':
      'This comment tries to tell an AI reviewer to ignore or approve the code. Delete it.',
    'SAST-SQLI-001':
      'The query is built by gluing request data into SQL. Use a parameterized query instead.',
    default: 'This finding was produced by a deterministic FullShield rule. See the remediation field.',
  },
  logic: [
    {
      when: 'findById(req.params.id)',
      unless: 'req.user',
      findings: [
        {
          ruleId: 'AI-IDOR-001',
          title: 'Insecure direct object reference',
          message: 'A record is loaded by request id without an ownership check.',
          fileHint: 'user',
          severity: 'medium',
        },
      ],
    },
    {
      when: 'Object.assign(user, req.body)',
      findings: [
        {
          ruleId: 'AI-MASSASSIGN-001',
          title: 'Mass assignment',
          message: 'Request body is written onto a user record without a field allowlist.',
          fileHint: 'profile',
          severity: 'medium',
        },
      ],
    },
  ],
  fix: {
    'AI-INJECT-001': {
      file: 'src/index.js',
      after: 'export function ok() {\n  return 1;\n}\n',
    },
  },
};

export function fixtureTriage(ruleId: string): TriageLabel {
  return RECORDED_FIXTURES.triage[ruleId] ?? RECORDED_FIXTURES.triage['default']!;
}

export function fixtureExplain(ruleId: string): string {
  return RECORDED_FIXTURES.explain[ruleId] ?? RECORDED_FIXTURES.explain['default']!;
}

export function fixtureLogic(prompt: string): LogicFixtureFinding[] {
  const out: LogicFixtureFinding[] = [];
  for (const row of RECORDED_FIXTURES.logic) {
    if (!prompt.includes(row.when)) {continue;}
    if (row.unless !== undefined && prompt.includes(row.unless)) {continue;}
    out.push(...row.findings);
  }
  return out;
}

export function fixtureFix(ruleId: string): { file: string; after: string } | undefined {
  return RECORDED_FIXTURES.fix[ruleId];
}

export function asAiFinding(
  seed: LogicFixtureFinding,
  file: string,
  line: number,
): Finding {
  return {
    id: `ai:${seed.ruleId}:${file}:${line}`,
    ruleId: seed.ruleId,
    module: 'sast',
    title: seed.title,
    severity: seed.severity,
    confidence: 'medium',
    file,
    line,
    message: seed.message,
    remediation: seed.title,
    references: [seed.ruleId],
    source: 'ai',
  };
}
