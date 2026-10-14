import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';

function finding(
  ruleId: string,
  title: string,
  message: string,
  file: string,
  severity: Finding['severity'] = 'high',
): Finding {
  return {
    id: makeFindingId(ruleId, file, message),
    ruleId,
    module: 'sast',
    title,
    severity,
    confidence: 'medium',
    file,
    message,
    remediation: 'Keep user text in the user role, never concatenate into the system prompt; do not send model output to sinks; require confirmation for dangerous tools; keep API keys server-side; set max_tokens.',
    cwe: 'CWE-1426',
  };
}

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'dist', '.git'].includes(entry.name)) continue;
      walk(full, out);
    } else if (entry.isFile() && /\.[cm]?[jt]sx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

export interface LlmScanOptions {
  experimental?: boolean;
}

/** Static LLM-app rules. Off unless experimental. */
export function scanLlmApp(dir: string, opts: LlmScanOptions = {}): Finding[] {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_LLM !== '1') return [];
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return [];
  const findings: Finding[] = [];
  for (const file of walk(dir)) {
    const rel = relative(dir, file) || file;
    const text = readFileSync(file, 'utf8');
    if (
      /role\s*:\s*['"]system['"]/.test(text) &&
      /content\s*:\s*['"][^'"]*['"]\s*\+|content\s*:\s*.*\+\s*req\.(body|query|params)/.test(text)
    ) {
      findings.push(
        finding(
          'LLM-001',
          'User input concatenated into an LLM system prompt',
          'User-controlled data is concatenated into a system-role message (OWASP LLM01).',
          rel,
        ),
      );
    }
    if (
      /\b(exec|execSync|execFile|spawn|eval|query)\s*\(\s*(completion|response|llm|output|answer|choices)/.test(
        text,
      ) ||
      /\.innerHTML\s*=\s*.*(completion|choices\[)/.test(text)
    ) {
      findings.push(
        finding(
          'LLM-002',
          'LLM output passed into a dangerous sink',
          'Model output reaches exec/eval/SQL/HTML without validation (OWASP LLM02).',
          rel,
        ),
      );
    }
    if (
      /name\s*:\s*['"](run_shell|shell|exec|write_file|send_payment)['"]/.test(text) &&
      !/require(Confirmation|Approval)|confirm(ation)?\s*:/.test(text)
    ) {
      findings.push(
        finding(
          'LLM-003',
          'Dangerous LLM tool without confirmation',
          'Function-calling exposes shell/file/payment tools without a confirmation step (OWASP LLM06).',
          rel,
        ),
      );
    }
    const browserish = /(^|\/)(public|client|browser|static)\//.test(rel.replaceAll('\\', '/'));
    if (browserish && /OPENAI_API_KEY|ANTHROPIC_API_KEY|sk-[a-zA-Z0-9]{8,}/.test(text)) {
      findings.push(
        finding(
          'LLM-004',
          'LLM API key exposed to a browser bundle',
          'An OpenAI/Anthropic-style key is present in a public/client file (OWASP LLM06/sensitive info).',
          rel,
          'critical',
        ),
      );
    }
    if (
      /chat\.completions\.create|messages\.create|anthropic\.messages/.test(text) &&
      !/max_tokens|max_completion_tokens|maxTokens/.test(text)
    ) {
      findings.push(
        finding(
          'LLM-005',
          'LLM call has no output length or cost limit',
          'chat/completions call does not set max_tokens (OWASP LLM10 unbounded consumption).',
          rel,
          'medium',
        ),
      );
    }
  }
  return findings;
}
