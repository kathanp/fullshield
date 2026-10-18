import { spawn } from 'node:child_process';
import { execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';

import { applyInlineSuppressions } from '../../core/suppression.js';
import type { Finding } from '../../core/finding.js';
import { makeFindingId } from '../../core/finding.js';
import { scanTextForSecretHits } from './index.js';
import type { SecretHit } from './types.js';

const execFileAsync = promisify(execFile);
const ZERO_HASH = /^0+$/;
const MAX_BLOB = 1024 * 1024;
const RAW_LINE =
  /^:(\d{6}) (\d{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([A-Z][0-9]*)\t(.+)$/;

export interface HistoryScanResult {
  findings: Finding[];
  hits: SecretHit[];
  /** Set when the commit cap stopped the walk before the oldest commit. */
  history?: string;
}

function gitError(error: unknown): Error {
  const detail =
    error instanceof Error ? error.message.split('\n')[0] ?? 'git failed' : String(error);
  return new Error(`--history requires a git repository and the git CLI (${detail})`);
}

async function gitOk(cwd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', ['-C', cwd, ...args], {
      encoding: 'utf8',
      maxBuffer: MAX_BLOB + 16_384,
    });
    return stdout;
  } catch (error) {
    throw gitError(error);
  }
}

async function readBlob(cwd: string, hash: string): Promise<string | undefined> {
  if (ZERO_HASH.test(hash)) return undefined;
  try {
    const sizeRaw = await gitOk(cwd, ['cat-file', '-s', hash]);
    const size = Number(sizeRaw.trim());
    if (!Number.isFinite(size) || size <= 0 || size > MAX_BLOB) return undefined;
    const { stdout } = await execFileAsync('git', ['-C', cwd, 'cat-file', 'blob', hash], {
      encoding: 'utf8',
      maxBuffer: MAX_BLOB + 16_384,
    });
    if (stdout.includes('\u0000')) return undefined;
    return stdout;
  } catch {
    return undefined;
  }
}

function remapHit(hit: SecretHit, file: string): SecretHit {
  const snippet = hit.finding.snippet;
  const line = hit.finding.line ?? 0;
  const id = makeFindingId(hit.finding.ruleId, file, `${line}|${snippet ?? 'file'}`);
  return {
    finding: { ...hit.finding, id, file },
    secret: hit.secret,
  };
}

interface BlobChange {
  commit: string;
  hash: string;
  path: string;
}

/** Stop history scans after this many commits. `FULLSHIELD_HISTORY_MAX` overrides it (1–5000). */
export function historyCommitLimit(raw = process.env.FULLSHIELD_HISTORY_MAX): number {
  if (raw === undefined || raw.trim() === '') return 500;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) return 500;
  return Math.min(parsed, 5000);
}

async function streamLogChanges(cwd: string, maxCommits: number): Promise<BlobChange[]> {
  const changes: BlobChange[] = [];
  await gitOk(cwd, ['rev-parse', '--is-inside-work-tree']);

  const child = spawn(
    'git',
    [
      '-C',
      cwd,
      'log',
      '--reverse',
      '--raw',
      '-p',
      '--no-abbrev',
      '--full-index',
      '--format=FSCOMMIT:%H',
      '--no-textconv',
      '--no-ext-diff',
      '-n',
      String(maxCommits),
      'HEAD',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );

  const stderrChunks: Buffer[] = [];
  child.stderr.on('data', (chunk: Buffer) => {
    stderrChunks.push(chunk);
  });
  const closed = new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (c) => resolve(c));
  });

  let current = '';
  const rl = createInterface({ input: child.stdout });
  for await (const line of rl) {
    if (line.startsWith('FSCOMMIT:')) {
      current = line.slice('FSCOMMIT:'.length).trim();
      continue;
    }
    const match = RAW_LINE.exec(line);
    if (match?.[3] !== undefined && match[4] !== undefined && match[6] !== undefined) {
      const newHash = match[4];
      const status = match[5] ?? '';
      if (status.startsWith('D') || ZERO_HASH.test(newHash) || current.length === 0) continue;
      const pathField = match[6];
      const path = pathField.includes('\t') ? (pathField.split('\t').pop() ?? pathField) : pathField;
      changes.push({ commit: current, hash: newHash, path });
    }
  }

  let code: number | null;
  try {
    code = await closed;
  } catch (error) {
    throw gitError(error);
  }
  if (code !== 0) {
    const err = Buffer.concat(stderrChunks).toString('utf8').trim();
    throw gitError(new Error(err.length > 0 ? err : `git log exited ${code}`));
  }
  return changes;
}

async function headSecretKeys(cwd: string): Promise<Set<string>> {
  const keys = new Set<string>();
  let ls: string;
  try {
    ls = await gitOk(cwd, ['ls-tree', '-r', '--full-tree', 'HEAD']);
  } catch {
    return keys;
  }
  const seen = new Map<string, SecretHit[]>();
  for (const line of ls.split('\n')) {
    const match = /^(\d{6}) blob ([0-9a-f]{40})\t(.+)$/.exec(line);
    if (match?.[2] === undefined || match[3] === undefined) continue;
    const hash = match[2];
    const path = match[3];
    let hits = seen.get(hash);
    if (hits === undefined) {
      const text = await readBlob(cwd, hash);
      if (text === undefined) continue;
      hits = scanTextForSecretHits(path, text);
      seen.set(hash, hits);
    }
    for (const hit of hits) {
      keys.add(`${hit.finding.ruleId}\0${hit.finding.snippet ?? ''}`);
    }
  }
  return keys;
}

/**
 * Scan every commit reachable from HEAD (`git log -p` streamed),
 * deduplicated by blob hash. Annotates first-introduced commit and still-at-HEAD.
 */
async function commitCount(cwd: string): Promise<number> {
  const raw = await gitOk(cwd, ['rev-list', '--count', 'HEAD']);
  const total = Number(raw.trim());
  return Number.isInteger(total) && total >= 0 ? total : 0;
}

export async function scanGitHistory(cwd: string, maxCommits = historyCommitLimit()): Promise<HistoryScanResult> {
  const total = await commitCount(cwd);
  const changes = await streamLogChanges(cwd, maxCommits);
  const blobHits = new Map<string, SecretHit[]>();
  const first = new Map<string, { hit: SecretHit; commit: string }>();

  for (const change of changes) {
    let hits = blobHits.get(change.hash);
    if (hits === undefined) {
      const text = await readBlob(cwd, change.hash);
      if (text === undefined) {
        blobHits.set(change.hash, []);
        continue;
      }
      const rawHits = scanTextForSecretHits(change.path, text);
      const allowed = new Set(
        applyInlineSuppressions(
          rawHits.map((h) => h.finding),
          { [change.path]: text },
        ).map((f) => f.id),
      );
      hits = rawHits.filter((h) => allowed.has(h.finding.id));
      blobHits.set(change.hash, hits);
    }
    for (const hit of hits) {
      const mapped = remapHit(hit, change.path);
      if (!first.has(mapped.finding.id)) {
        first.set(mapped.finding.id, { hit: mapped, commit: change.commit });
      }
    }
  }

  const atHead = await headSecretKeys(cwd);
  const hits: SecretHit[] = [];
  for (const { hit, commit } of first.values()) {
    const stillAtHead = atHead.has(`${hit.finding.ruleId}\0${hit.finding.snippet ?? ''}`);
    hits.push({
      finding: { ...hit.finding, introducedIn: commit, stillAtHead },
      secret: hit.secret,
    });
  }
  const scanned = Math.min(maxCommits, total);
  const history = total > maxCommits ? `scanned ${scanned} of ${total} commits` : undefined;
  return {
    findings: hits.map((h) => h.finding),
    hits,
    ...(history !== undefined ? { history } : {}),
  };
}
