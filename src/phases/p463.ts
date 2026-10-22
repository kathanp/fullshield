/**
 * Phase 463. Node flags in start scripts.
 * Off unless FULLSHIELD_EXPERIMENTAL_NODEFLAGS=1.
 * Flag off: the baseline finding list is returned unchanged.
 * The command string is tokenized and is not spawned.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NODEFLAGS';
export const INSPECT_RULE = 'CONFIG-INSPECT-001';
export const PARSER_RULE = 'CONFIG-NODE-PARSER-001';
export const EVAL_RULE = 'CONFIG-NODE-EVAL-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

export function tokenize(command: string): string[] {
  const tokens: string[] = [];
  const pattern = /"[^"]*"|'[^']*'|\S+/g;
  for (const match of command.matchAll(pattern)) {
    const token = match[0] ?? '';
    tokens.push(token.replace(/^['"]|['"]$/g, ''));
  }
  return tokens;
}

function inspectHost(token: string): string | null {
  if (token === '--inspect' || token === '--inspect-brk') {
    return '';
  }
  const match = /^--inspect(?:-brk)?=(.+)$/.exec(token);
  if (match?.[1] === undefined) {
    return null;
  }
  const host = match[1].replace(/:\d+$/, '');
  return host;
}

function severityFor(scriptName: string): 'medium' | 'high' {
  if (scriptName === 'dev' || scriptName === 'start:dev') {
    return 'medium';
  }
  return 'high';
}

export function scanCommand(scriptName: string, command: string, file = 'package.json'): PhaseFinding[] {
  const findings: PhaseFinding[] = [];
  for (const token of tokenize(command)) {
    const host = inspectHost(token);
    if (host !== null && !LOOPBACK.has(host)) {
      const severity = severityFor(scriptName);
      findings.push({
        ruleId: INSPECT_RULE,
        severity,
        file,
        line: 1,
        message: `--inspect on script name ${scriptName}`,
      });
    }
    if (token === '--insecure-http-parser') {
      findings.push({ ruleId: PARSER_RULE, severity: 'medium', file, line: 1, message: '--insecure-http-parser' });
    }
    if (token.startsWith('--eval')) {
      const literal = token.includes('=') ? token.slice(token.indexOf('=') + 1) : '';
      if (SECRET.test(literal)) {
        findings.push({ ruleId: EVAL_RULE, severity: 'high', file, line: 1, message: '--eval of a secret-shaped literal', snippet: '****' });
      }
    }
  }
  return findings;
}

export function scanScripts(scripts: Readonly<Record<string, string>>, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  for (const [name, command] of Object.entries(scripts)) {
    findings.push(...scanCommand(name, command));
  }
  return [...baseline, ...findings];
}
