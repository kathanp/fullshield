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

interface GitRef {
  sha: string;
  ref: string;
}

function readText(reader: GitReader, ...parts: string[]): string {
  return reader.read(gitPath(...parts))?.toString('utf8') ?? '';
}

function pushSha(refs: GitRef[], sha: string, ref: string): void {
  if (/^[0-9a-f]{40}$/.test(sha)) {
    refs.push({ sha, ref });
  }
}

function packedRefs(reader: GitReader): GitRef[] {
  const refs: GitRef[] = [];
  for (const line of readText(reader, 'packed-refs').split('\n')) {
    const match = /^([0-9a-f]{40})\s+(\S+)/.exec(line.trim());
    if (match?.[1] !== undefined && match[2] !== undefined) {
      refs.push({ sha: match[1], ref: match[2] });
    }
  }
  return refs;
}

function headRef(reader: GitReader, refs: GitRef[]): void {
  const head = readText(reader, 'HEAD').trim();
  if (/^[0-9a-f]{40}$/.test(head)) {
    refs.push({ sha: head, ref: 'HEAD' });
    return;
  }
  if (!head.startsWith('ref: ')) {
    return;
  }
  const name = head.slice(5).trim();
  pushSha(refs, readText(reader, ...name.split('/')).trim(), name);
}

function reflogRefs(reader: GitReader): GitRef[] {
  const refs: GitRef[] = [];
  for (const line of readText(reader, 'logs', 'HEAD').split('\n')) {
    const next = /^[0-9a-f]{40} ([0-9a-f]{40}) /.exec(line)?.[1];
    if (next !== undefined && next !== '0'.repeat(40)) {
      refs.push({ sha: next, ref: 'reflog' });
    }
  }
  return refs;
}

function refsOf(reader: GitReader): GitRef[] {
  const refs = packedRefs(reader);
  headRef(reader, refs);
  pushSha(refs, readText(reader, 'refs', 'stash').trim(), 'refs/stash');
  refs.push(...reflogRefs(reader));
  return refs;
}

function safeList(reader: GitReader, path: string): readonly string[] {
  try {
    return reader.list(path);
  } catch {
    return [];
  }
}

interface GitWalk {
  findings: GitFinding[];
  events: GitScan['events'];
  claimedClean: boolean;
  used: number;
  maxBytes: number;
}

function noteEvent(state: GitWalk, file: string, detail: string): void {
  state.events.push({ code: 271, file, detail });
  state.claimedClean = false;
}

function noteAlternates(reader: GitReader, state: GitWalk): void {
  for (const line of readText(reader, 'objects', 'info', 'alternates').split('\n')) {
    const target = line.trim();
    if (target.length === 0) {
      continue;
    }
    noteEvent(state, target, 'alternate not followed');
  }
}

function loadStore(reader: GitReader, sha: string, state: GitWalk): Buffer | undefined {
  const raw = reader.read(gitPath('objects', sha.slice(0, 2), sha.slice(2)));
  if (raw === undefined) {
    return undefined;
  }
  const store = inflate(raw);
  if (store === undefined) {
    noteEvent(state, sha, 'corrupt git object');
  }
  return store;
}

function enqueueSplit(split: { type: string; payload: Buffer }, item: GitRef, formats: readonly SecretFormat[], queue: GitRef[], state: GitWalk): void {
  if (split.type === 'commit') {
    const tree = /^tree ([0-9a-f]{40})/m.exec(split.payload.toString('utf8'))?.[1];
    if (tree !== undefined) {
      queue.push({ sha: tree, ref: item.ref });
    }
    return;
  }
  if (split.type === 'tree') {
    for (const sha of treeShas(split.payload)) {
      queue.push({ sha, ref: item.ref });
    }
    return;
  }
  if (split.type !== 'blob') {
    return;
  }
  const matched = matchGrammar(split.payload.toString('utf8'), formats);
  if (matched === undefined) {
    return;
  }
  state.findings.push({
    ruleId: 'SECRETS-FORMAT-001',
    severity: 'high',
    file: `${item.sha} ${item.ref}`,
    line: 1,
    message: `git-object ${item.sha} on ${item.ref} matches ${matched.id}. The blob is not in the working tree.`,
    witness: 'git-object',
  });
}

function takeObject(reader: GitReader, item: GitRef, formats: readonly SecretFormat[], queue: GitRef[], state: GitWalk): 'stop' | 'next' {
  if (state.used > state.maxBytes) {
    noteEvent(state, item.sha, 'git object fuel exhausted');
    return 'stop';
  }
  const store = loadStore(reader, item.sha, state);
  if (store === undefined) {
    return 'next';
  }
  state.used += store.length;
  const split = splitHeader(store);
  if (split === undefined) {
    noteEvent(state, item.sha, 'corrupt git object');
    return 'next';
  }
  enqueueSplit(split, item, formats, queue, state);
  return 'next';
}

function walkObjects(reader: GitReader, formats: readonly SecretFormat[], state: GitWalk): void {
  const seen = new Set<string>();
  const queue = refsOf(reader);
  while (queue.length > 0) {
    const item = queue.shift();
    if (item === undefined || seen.has(item.sha)) {
      continue;
    }
    seen.add(item.sha);
    if (takeObject(reader, item, formats, queue, state) === 'stop') {
      break;
    }
  }
}

function scanPacks(reader: GitReader, state: GitWalk): void {
  for (const name of safeList(reader, gitPath('objects', 'pack'))) {
    if (!name.endsWith('.pack')) {
      continue;
    }
    const bytes = reader.read(gitPath('objects', 'pack', name));
    if (bytes === undefined || bytes.length < 4 || bytes.subarray(0, 4).toString('utf8') !== 'PACK') {
      noteEvent(state, name, 'corrupt pack');
    }
  }
}

export function scanGit(reader: GitReader, formats: readonly SecretFormat[], maxBytes = 1_000_000): GitScan {
  if (!enabled()) {
    return { findings: [], events: [], claimedClean: true };
  }
  const state: GitWalk = { findings: [], events: [], claimedClean: true, used: 0, maxBytes };
  noteAlternates(reader, state);
  walkObjects(reader, formats, state);
  scanPacks(reader, state);
  return { findings: state.findings, events: state.events, claimedClean: state.claimedClean };
}
