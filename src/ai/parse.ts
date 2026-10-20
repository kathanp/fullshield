export type TriageVerdict = 'true-positive' | 'likely-false-positive' | 'needs-review';

export interface LiveTriage {
  verdict: TriageVerdict;
  reasoning: string;
  exploitScenario: string;
}

export interface LiveLogicFinding {
  ruleId: string;
  title: string;
  message: string;
  file?: string;
  line?: number;
  severity?: 'low' | 'medium';
}

export interface LiveFix {
  file: string;
  after: string;
}

const VERDICTS = new Set<TriageVerdict>(['true-positive', 'likely-false-positive', 'needs-review']);

/** Pull a JSON object out of raw model text (fences, leading prose, etc.). */
export function extractJson(text: string): unknown {
  const trimmed = text.trim();
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(trimmed);
  const candidate = fenced?.[1]?.trim() ?? trimmed;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end <= start) {throw new SyntaxError('no JSON object in model output');}
  return JSON.parse(candidate.slice(start, end + 1)) as unknown;
}

export function asTriage(value: unknown): LiveTriage | undefined {
  if (typeof value !== 'object' || value === null) {return undefined;}
  const rec = value as Record<string, unknown>;
  if (typeof rec.verdict !== 'string' || !VERDICTS.has(rec.verdict as TriageVerdict)) {return undefined;}
  return {
    verdict: rec.verdict as TriageVerdict,
    reasoning: typeof rec.reasoning === 'string' ? rec.reasoning : '',
    exploitScenario: typeof rec.exploitScenario === 'string' ? rec.exploitScenario : '',
  };
}

export function asExplanation(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim().length > 0) {return value;}
  if (typeof value !== 'object' || value === null) {return undefined;}
  const rec = value as Record<string, unknown>;
  if (typeof rec.explanation === 'string' && rec.explanation.trim().length > 0) {return rec.explanation;}
  return undefined;
}

export function asLogicFindings(value: unknown): LiveLogicFinding[] | undefined {
  if (typeof value !== 'object' || value === null) {return undefined;}
  const rec = value as Record<string, unknown>;
  const raw = rec.findings;
  if (!Array.isArray(raw)) {return undefined;}
  const out: LiveLogicFinding[] = [];
  for (const item of raw) {
    if (typeof item !== 'object' || item === null) {continue;}
    const row = item as Record<string, unknown>;
    if (typeof row.ruleId !== 'string' || typeof row.message !== 'string') {continue;}
    out.push({
      ruleId: row.ruleId,
      title: typeof row.title === 'string' ? row.title : row.ruleId,
      message: row.message,
      file: typeof row.file === 'string' ? row.file : undefined,
      line: typeof row.line === 'number' ? row.line : undefined,
      severity: row.severity === 'low' || row.severity === 'medium' ? row.severity : 'medium',
    });
  }
  return out;
}

export function asFix(value: unknown): LiveFix | undefined {
  if (typeof value !== 'object' || value === null) {return undefined;}
  const rec = value as Record<string, unknown>;
  if (typeof rec.file !== 'string' || typeof rec.after !== 'string') {return undefined;}
  if (rec.file.length === 0) {return undefined;}
  return { file: rec.file, after: rec.after };
}

export function modeInstruction(mode: string): string {
  if (mode === 'triage') {
    return (
      'Reply with JSON only: ' +
      '{"verdict":"true-positive"|"likely-false-positive"|"needs-review","reasoning":"string","exploitScenario":"string"}'
    );
  }
  if (mode === 'explain') {
    return 'Reply with JSON only: {"explanation":"plain English for a junior developer, 2-6 sentences"}';
  }
  if (mode === 'logic') {
    return (
      'Hunt IDOR, missing ownership checks, privilege escalation, and mass assignment. ' +
      'Reply with JSON only: {"findings":[{"ruleId":"AI-IDOR-001"|"AI-MASSASSIGN-001","title":"string","message":"string","file":"relative path","line":1,"severity":"medium"}]} ' +
      'Use an empty findings array if nothing is wrong. Confidence is medium; do not invent files.'
    );
  }
  return (
    'Draft a minimal patch that removes the vulnerability. Reply with JSON only: ' +
    '{"file":"relative path","after":"complete new file contents"}. Do not write anything else.'
  );
}
