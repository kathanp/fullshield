import { runCaptured } from '../../core/git.js';

export const BUMP_PR_FLAG = 'FULLSHIELD_EXPERIMENTAL_BUMP_PR';

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

export interface GhResult {
  status: number;
  stdout: string;
  stderr: string;
}

export type GhRunner = (args: string[]) => Promise<GhResult>;

export interface RankedBump {
  name: string;
  from: string;
  to: string;
  severity: 'critical' | 'high';
  reachability: 'reachable';
  advisory: string;
  rank: number;
}

interface BumpFix {
  kind?: string;
  diff?: string;
}

interface BumpFinding {
  ruleId?: string;
  severity?: string;
  reachability?: string;
  snippet?: string;
  references?: string[];
  fix?: BumpFix;
}

interface ScanDocument {
  findings?: BumpFinding[];
}

const SEVERITY_ORDER: Record<'critical' | 'high', number> = { critical: 0, high: 1 };

export function assertBumpPrEnabled(): void {
  if (process.env[BUMP_PR_FLAG] !== '1') {
    fail(`bumps requires ${BUMP_PR_FLAG}=1`);
  }
}

export function ghStatus(error: { code?: unknown } | null): number {
  if (error === null) {return 0;}
  return typeof error.code === 'number' ? error.code : 1;
}

export function defaultGhRunner(args: string[]): Promise<GhResult> {
  return runCaptured('gh', args);
}

function parseSnippet(snippet: string): { name: string; from: string } | undefined {
  const at = snippet.lastIndexOf('@');
  if (at <= 0) {return undefined;}
  const name = snippet.slice(0, at);
  const from = snippet.slice(at + 1);
  if (name.length === 0 || from.length === 0) {return undefined;}
  return { name, from };
}

function parseTo(diff: string): string | undefined {
  const match = / to ([^\s]+)\s*$/m.exec(diff);
  if (match?.[1] === undefined || match[1].length === 0) {return undefined;}
  return match[1];
}

function isOpenSeverity(value: string | undefined): value is 'critical' | 'high' {
  return value === 'critical' || value === 'high';
}

/** Reachable high and critical bumps only, ranked critical then name then advisory. */
export function rankBumpsFromScan(doc: ScanDocument): RankedBump[] {
  const kept: Array<Omit<RankedBump, 'rank'>> = [];
  for (const finding of doc.findings ?? []) {
    if (finding.ruleId !== 'DEPS-VULN-001') {continue;}
    if (finding.reachability !== 'reachable') {continue;}
    if (!isOpenSeverity(finding.severity)) {continue;}
    if (finding.fix?.kind !== 'dependency-bump' || typeof finding.fix.diff !== 'string') {continue;}
    if (typeof finding.snippet !== 'string') {continue;}
    const parsed = parseSnippet(finding.snippet);
    const to = parseTo(finding.fix.diff);
    const advisory = finding.references?.[0];
    if (parsed === undefined || to === undefined || advisory === undefined || advisory.length === 0) {continue;}
    kept.push({
      name: parsed.name,
      from: parsed.from,
      to,
      severity: finding.severity,
      reachability: 'reachable',
      advisory,
    });
  }
  kept.sort((a, b) => {
    const severity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severity !== 0) {return severity;}
    const name = a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    if (name !== 0) {return name;}
    return a.advisory < b.advisory ? -1 : a.advisory > b.advisory ? 1 : 0;
  });
  return kept.map((row, index) => ({ ...row, rank: index + 1 }));
}

export function bumpPullRequestArgs(item: RankedBump): string[] {
  const title = `chore: bump ${item.name} to ${item.to}`;
  const body = [
    `Reachable ${item.severity} advisory ${item.advisory}.`,
    `Bump ${item.name} from ${item.from} to ${item.to} with the package manager.`,
    'FullShield does not edit the lockfile and does not post pull-request comments.',
    'A person accepts this pull request.',
  ].join(' ');
  return ['pr', 'create', '--title', title, '--body', body];
}

export async function openBumpPullRequests(
  items: readonly RankedBump[],
  runGh?: GhRunner,
): Promise<{ urls: string[]; commands: string[][] }> {
  const commands = items.map((item) => bumpPullRequestArgs(item));
  const urls: string[] = [];
  if (runGh === undefined) {return { urls, commands };}
  for (const args of commands) {
    const result = await runGh(args);
    if (result.status !== 0) {
      fail(`gh pr create failed (${BUMP_PR_FLAG})`);
    }
    const url = result.stdout.trim().split('\n').find((line) => line.startsWith('http'));
    if (url !== undefined) {urls.push(url);}
  }
  return { urls, commands };
}

export function rankedBumpsFromText(text: string): RankedBump[] {
  let doc: ScanDocument;
  try {
    doc = JSON.parse(text) as ScanDocument;
  } catch {
    fail(`cannot read bumps file (${BUMP_PR_FLAG})`);
  }
  if (typeof doc !== 'object' || doc === null) {
    fail(`cannot read bumps file (${BUMP_PR_FLAG})`);
  }
  return rankBumpsFromScan(doc);
}

export function rankBumpsJson(text: string): string {
  return `${JSON.stringify(rankedBumpsFromText(text))}\n`;
}
