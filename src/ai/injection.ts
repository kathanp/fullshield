import { makeFindingId, type Finding } from '../core/finding.js';

const PHRASES = [/ignore previous/i, /mark as safe/i, /ai reviewer/i];

function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}

/** Deterministic prompt-injection comment detector (spec §16.2). */
export function scanPromptInjection(file: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (!isCommentLine(line)) {return;}
    if (!PHRASES.some((p) => p.test(line))) {return;}
    findings.push({
      id: makeFindingId('AI-INJECT-001', file, `${index + 1}|${line.trim()}`),
      ruleId: 'AI-INJECT-001',
      module: 'sast',
      title: 'Prompt-injection comment aimed at AI reviewers',
      severity: 'medium',
      confidence: 'high',
      file,
      line: index + 1,
      snippet: line.trim().slice(0, 120),
      message: 'Code contains text attempting to manipulate AI reviewers.',
      remediation: 'Remove comments that try to instruct an AI reviewer.',
      references: ['AI-INJECT-001'],
      source: 'deterministic',
    });
  });
  return findings;
}
