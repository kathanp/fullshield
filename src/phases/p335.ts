/**
 * Phase 335. Local git objects.
 * Off unless FULLSHIELD_EXPERIMENTAL_GITOBJECTS=1.
 * Reads blobs through the caller. Does not spawn git and does not follow alternates.
 */

import { inflateSync } from 'node:zlib';

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GITOBJECTS';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface GitReader {
  read(path: string): Buffer | undefined;
  list(path: string): readonly string[];
}

export interface GitFinding {
  ruleId: 'SECRETS-FORMAT-001';
  severity: 'high';
  file: string;
  line: number;
  message: string;
  witness: 'git-object';
}

export interface GitScan {
  findings: GitFinding[];
  events: { code: 271; file: string; detail: string }[];
  claimedClean: boolean;
}

function gitPath(...parts: string[]): string {
  return ['.git', ...parts].join('/');
}

function inflate(bytes: Buffer | undefined): Buffer | undefined {
  if (bytes === undefined) {
    return undefined;
  }
  try {
    return inflateSync(bytes);
  } catch {
    return undefined;
  }
}

function splitHeader(store: Buffer): { type: string; payload: Buffer } | undefined {
  const nul = store.indexOf(0);
  if (nul < 0) {
    return undefined;
  }
  const type = store.subarray(0, nul).toString('utf8').split(' ')[0];
  if (type === undefined) {
    return undefined;
  }
  return { type, payload: store.subarray(nul + 1) };
}

function treeShas(payload: Buffer): string[] {
  const shas: string[] = [];
  let offset = 0;
  while (offset < payload.length) {
    const nul = payload.indexOf(0, offset);
    if (nul < 0 || nul + 21 > payload.length) {
      break;
    }
    shas.push(payload.subarray(nul + 1, nul + 21).toString('hex'));
    offset = nul + 21;
  }
  return shas;
}

function refsOf(reader: GitReader): { sha: string; ref: string }[] {
  const refs: { sha: string; ref: string }[] = [];
  const packed = reader.read(gitPath('packed-refs'))?.toString('utf8') ?? '';
  for (const line of packed.split('\n')) {
    const match = /^([0-9a-f]{40})\s+(\S+)/.exec(line.trim());
    if (match?.[1] !== undefined && match[2] !== undefined) {
      refs.push({ sha: match[1], ref: match[2] });
    }
  }
  const head = reader.read(gitPath('HEAD'))?.toString('utf8').trim() ?? '';
  if (/^[0-9a-f]{40}$/.test(head)) {
    refs.push({ sha: head, ref: 'HEAD' });
  } else if (head.startsWith('ref: ')) {
    const target = reader.read(gitPath(...head.slice(5).trim().split('/')))?.toString('utf8').trim() ?? '';
    if (/^[0-9a-f]{40}$/.test(target)) {
      refs.push({ sha: target, ref: head.slice(5).trim() });
    }
  }
  const stash = reader.read(gitPath('refs', 'stash'))?.toString('utf8').trim() ?? '';
  if (/^[0-9a-f]{40}$/.test(stash)) {
    refs.push({ sha: stash, ref: 'refs/stash' });
  }
  const reflog = reader.read(gitPath('logs', 'HEAD'))?.toString('utf8') ?? '';
  for (const line of reflog.split('\n')) {
    const next = /^[0-9a-f]{40} ([0-9a-f]{40}) /.exec(line)?.[1];
    if (next !== undefined && next !== '0'.repeat(40)) {
      refs.push({ sha: next, ref: 'reflog' });
    }
  }
  return refs;
}

function safeList(reader: GitReader, path: string): readonly string[] {
  try {
    return reader.list(path);
  } catch {
    return [];
  }
}

export function scanGit(reader: GitReader, formats: readonly SecretFormat[], maxBytes = 1_000_000): GitScan {
  if (!enabled()) {
    return { findings: [], events: [], claimedClean: true };
  }
  const findings: GitFinding[] = [];
  const events: GitScan['events'] = [];
  let claimedClean = true;
  let used = 0;
  for (const line of (reader.read(gitPath('objects', 'info', 'alternates'))?.toString('utf8') ?? '').split('\n')) {
    const target = line.trim();
    if (target.length === 0) {
      continue;
    }
    events.push({ code: 271, file: target, detail: 'alternate not followed' });
    claimedClean = false;
  }
  const seen = new Set<string>();
  const queue = refsOf(reader);
  while (queue.length > 0) {
    const item = queue.shift();
    if (item === undefined || seen.has(item.sha)) {
      continue;
    }
    seen.add(item.sha);
    if (used > maxBytes) {
      events.push({ code: 271, file: item.sha, detail: 'git object fuel exhausted' });
      claimedClean = false;
      break;
    }
    const raw = reader.read(gitPath('objects', item.sha.slice(0, 2), item.sha.slice(2)));
    const store = raw === undefined ? undefined : inflate(raw);
    if (raw !== undefined && store === undefined) {
      events.push({ code: 271, file: item.sha, detail: 'corrupt git object' });
      claimedClean = false;
      continue;
    }
    if (store === undefined) {
      continue;
    }
    used += store.length;
    const split = splitHeader(store);
    if (split === undefined) {
      events.push({ code: 271, file: item.sha, detail: 'corrupt git object' });
      claimedClean = false;
      continue;
    }
    if (split.type === 'commit') {
      const tree = /^tree ([0-9a-f]{40})/m.exec(split.payload.toString('utf8'))?.[1];
      if (tree !== undefined) {
        queue.push({ sha: tree, ref: item.ref });
      }
    } else if (split.type === 'tree') {
      for (const sha of treeShas(split.payload)) {
        queue.push({ sha, ref: item.ref });
      }
    } else if (split.type === 'blob') {
      const matched = matchGrammar(split.payload.toString('utf8'), formats);
      if (matched !== undefined) {
        findings.push({
          ruleId: 'SECRETS-FORMAT-001',
          severity: 'high',
          file: `${item.sha} ${item.ref}`,
          line: 1,
          message: `git-object ${item.sha} on ${item.ref} matches ${matched.id}. The blob is not in the working tree.`,
          witness: 'git-object',
        });
      }
    }
  }
  for (const name of safeList(reader, gitPath('objects', 'pack'))) {
    if (!name.endsWith('.pack')) {
      continue;
    }
    const bytes = reader.read(gitPath('objects', 'pack', name));
    if (bytes === undefined || bytes.length < 4 || bytes.subarray(0, 4).toString('utf8') !== 'PACK') {
      events.push({ code: 271, file: name, detail: 'corrupt pack' });
      claimedClean = false;
    }
  }
  return { findings, events, claimedClean };
}
