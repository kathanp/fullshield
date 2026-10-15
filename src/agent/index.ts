import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { scan } from '../core/engine.js';
import { severityRank, sortFindings, type Finding } from '../core/finding.js';
import { applyUnifiedDiff, proposeFix } from '../fixer/patches.js';

const PROTECTED = new Set(['main', 'master', 'develop']);

export interface AgentPr {
  number: number;
  url: string;
  branch: string;
  files: string[];
  ruleId: string;
}

export interface AgentResult {
  skipped?: boolean;
  prs: AgentPr[];
  stoppedOnTestFailure?: boolean;
  pushedToProtected: boolean;
  merged: boolean;
}

export interface AgentOptions {
  cwd?: string;
  experimental?: boolean;
  maxPrs?: number;
  maxFilesPerPr?: number;
  apiBase?: string;
  token?: string;
  repo?: string;
  remote?: string;
  runTests?: (cwd: string) => Promise<{ ok: boolean; output: string }>;
  fetchImpl?: typeof fetch;
}

export function assertLocalAgentApi(url: string): true {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('agent API URL is invalid; use a localhost mock (never a real network)');
  }
  const host = parsed.hostname.toLowerCase();
  if (host !== '127.0.0.1' && host !== 'localhost') {
    throw new Error('agent refuses non-localhost API hosts (no real GitHub/GitLab network)');
  }
  return true;
}

function npmBin(): string {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function revertAgentFile(cwd: string, file: string, original: string, existed: boolean): void {
  const path = join(cwd, file);
  if (!existed) {
    try {
      unlinkSync(path);
    } catch {
      writeFileSync(path, original, 'utf8');
    }
    return;
  }
  writeFileSync(path, original, 'utf8');
}

function currentBranch(cwd: string): string {
  return git(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']);
}

function defaultTests(cwd: string): { ok: boolean; output: string } {
  try {
    const pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as { scripts?: { test?: string } };
    if (!pkg.scripts?.test) return { ok: true, output: 'no test script' };
    const out = execFileSync(npmBin(), ['test', '--silent'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { ok: true, output: out };
  } catch (error) {
    return { ok: false, output: error instanceof Error ? error.message : String(error) };
  }
}

function sourceFor(finding: Finding, cwd: string): { file: string; source: string } | undefined {
  const file = finding.file;
  if (file === undefined) return undefined;
  const target = finding.ruleId === 'SECRET-ENVFILE-001' ? '.gitignore' : file;
  const path = join(cwd, target);
  const source = existsSync(path) ? readFileSync(path, 'utf8') : '';
  return { file: target, source };
}

async function openPull(
  opts: AgentOptions,
  body: { title: string; head: string; base: string; body: string },
): Promise<{ number: number; url: string }> {
  const apiBase = opts.apiBase ?? '';
  assertLocalAgentApi(apiBase);
  const repo = opts.repo ?? 'acme/app';
  const fetchFn = opts.fetchImpl ?? fetch;
  const res = await fetchFn(`${apiBase.replace(/\/$/, '')}/repos/${repo}/pulls`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${opts.token ?? 'test-token'}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`mock GitHub PR create failed: ${res.status}`);
  }
  const json = (await res.json()) as { number?: number; html_url?: string };
  return { number: json.number ?? 1, url: json.html_url ?? `${apiBase}/pr/1` };
}

export async function runAgent(options: AgentOptions = {}): Promise<AgentResult> {
  const experimental = options.experimental === true || process.env.FULLSHIELD_EXPERIMENTAL_AGENT === '1';
  if (!experimental) {
    return { skipped: true, prs: [], pushedToProtected: false, merged: false };
  }
  const cwd = resolve(options.cwd ?? process.cwd());
  const apiBase = options.apiBase ?? process.env.FULLSHIELD_AGENT_API ?? '';
  assertLocalAgentApi(apiBase);
  const maxPrs = Math.max(1, options.maxPrs ?? 3);
  const maxFiles = Math.max(1, options.maxFilesPerPr ?? 3);
  const remote = options.remote ?? 'origin';
  const baseBranch = currentBranch(cwd);
  if (PROTECTED.has(baseBranch) === false && baseBranch !== 'HEAD') {
    // stay on current; still never push a protected name
  }

  const scanned = await scan({ cwd, offline: true });
  const ranked = sortFindings(scanned.findings).filter((f) => severityRank(f.severity) >= severityRank('medium'));
  const prs: AgentPr[] = [];
  let stoppedOnTestFailure = false;

  for (const finding of ranked) {
    if (prs.length >= maxPrs) break;
    const src = sourceFor(finding, cwd);
    if (src === undefined) continue;
    const proposed = proposeFix(
      finding.ruleId === 'SECRET-ENVFILE-001' ? { ...finding, file: src.file } : finding,
      src.source,
    );
    if (proposed === undefined || proposed.safe !== true) continue;
    const files = [src.file].slice(0, maxFiles);
    if (files.length === 0) continue;

    const branch = `fullshield/agent-${finding.ruleId.toLowerCase()}-${prs.length + 1}`;
    if (PROTECTED.has(branch)) {
      throw new Error('refusing to use a protected branch name');
    }
    git(cwd, ['checkout', '-B', branch, baseBranch]);
    const targetPath = join(cwd, src.file);
    const existed = existsSync(targetPath);
    const after = applyUnifiedDiff(src.source, proposed.diff);
    writeFileSync(targetPath, after, 'utf8');

    const tests = options.runTests ? await options.runTests(cwd) : defaultTests(cwd);
    if (!tests.ok) {
      revertAgentFile(cwd, src.file, src.source, existed);
      git(cwd, ['checkout', baseBranch]);
      stoppedOnTestFailure = true;
      break;
    }

    git(cwd, ['add', '--', ...files]);
    git(cwd, ['-c', 'user.email=agent@fullshield.local', '-c', 'user.name=FullShield Agent', 'commit', '-m', `fix: ${finding.ruleId}`]);
    git(cwd, ['push', remote, `HEAD:${branch}`]);
    if (PROTECTED.has(branch)) {
      throw new Error('refusing to push a protected branch');
    }

    const opened = await openPull(options, {
      title: `fix: ${finding.ruleId}`,
      head: branch,
      base: PROTECTED.has(baseBranch) ? baseBranch : 'main',
      body: [
        finding.message,
        finding.remediation,
        `Proof: safe rule-based patch for ${finding.ruleId} on ${files.join(', ')}.`,
        `Tests: ${tests.output.slice(0, 500) || 'passed'}`,
        'This PR is not merged. FullShield never merges and never pushes to protected branches.',
      ].join('\n\n'),
    });
    prs.push({ ...opened, branch, files, ruleId: finding.ruleId });
    git(cwd, ['checkout', baseBranch]);
  }

  return { prs, stoppedOnTestFailure, pushedToProtected: false, merged: false };
}
