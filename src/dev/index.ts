import { watch } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { scan } from '../core/engine.js';
import { type Finding, type ModuleName } from '../core/finding.js';
import { lineIndependentFingerprint } from '../core/fingerprint.js';
import { walkFiles } from '../core/fileWalker.js';
import { closeAllDbHandles } from '../core/sqlite.js';

export const DEV_FLAG = 'FULLSHIELD_EXPERIMENTAL_DEV';
const DEBOUNCE_MS = 300;
const SOURCE = /\.[cm]?[jt]sx?$/;
const MANIFESTS = new Set([
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
]);

export class DevError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DevError';
  }
}

export interface DevOptions {
  cwd: string;
  out: (line: string) => void;
  pollIntervalMs?: number;
  /** When set, overrides process.platform. Linux uses polling. */
  platform?: NodeJS.Platform;
}

export interface DevSession {
  done: Promise<void>;
  close(): Promise<void>;
}

interface LoopState {
  cwd: string;
  out: (line: string) => void;
  previous: Finding[];
  mtimes: Map<string, number>;
  closed: boolean;
}

interface Stoppable {
  close(): void;
}

export function devEnabled(): boolean {
  return process.env[DEV_FLAG] === '1';
}

function pollMs(explicit: number | undefined): number {
  if (explicit !== undefined && Number.isFinite(explicit) && explicit >= 1) {return Math.floor(explicit);}
  const raw = process.env.FULLSHIELD_DEV_POLL_MS;
  if (raw === undefined || raw.length === 0) {return 1000;}
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 1) {return 1000;}
  return Math.floor(parsed);
}

function recursiveWatch(platform: NodeJS.Platform): boolean {
  return platform === 'darwin' || platform === 'win32';
}

function skipPath(rel: string): boolean {
  return rel.split('/').some((part) => part === '.git' || part === 'node_modules' || part === '.fullshield' || part === 'dist' || part === 'coverage');
}

function baseName(rel: string): string {
  const norm = rel.replace(/\\/g, '/');
  const slash = norm.lastIndexOf('/');
  return slash < 0 ? norm : norm.slice(slash + 1);
}

function isManifest(rel: string): boolean {
  return MANIFESTS.has(baseName(rel));
}

function toPosix(rel: string): string {
  return rel.replace(/\\/g, '/').replace(/^\.\//, '');
}

function normalizePosix(path: string): string {
  const parts: string[] = [];
  for (const part of path.split('/')) {
    if (part === '' || part === '.') {continue;}
    if (part === '..') {parts.pop();}
    else {parts.push(part);}
  }
  return parts.join('/');
}

function resolveSpec(fromFile: string, spec: string, files: ReadonlySet<string>): string | undefined {
  const slash = fromFile.lastIndexOf('/');
  const dir = slash < 0 ? '' : fromFile.slice(0, slash);
  const joined = dir.length === 0 ? spec : `${dir}/${spec}`;
  const base = normalizePosix(joined);
  const candidates = [base, `${base}.js`, `${base}.ts`, `${base}.mjs`, `${base}.cjs`, `${base}.jsx`, `${base}.tsx`, `${base}/index.js`, `${base}/index.ts`];
  return candidates.find((candidate) => files.has(candidate));
}

function reverseClosure(sources: ReadonlyMap<string, string>, roots: readonly string[]): string[] {
  const files = new Set(sources.keys());
  const reverse = new Map<string, string[]>();
  const specRe = /(?:\brequire\(\s*|\bfrom\s+|import\s*\(\s*)['"](\.[^'"]+)['"]/g;
  for (const [file, text] of sources) {
    for (const match of text.matchAll(specRe)) {
      const spec = match[1];
      if (spec === undefined) {continue;}
      const resolved = resolveSpec(file, spec, files);
      if (resolved === undefined) {continue;}
      const list = reverse.get(resolved);
      if (list === undefined) {reverse.set(resolved, [file]);}
      else {list.push(file);}
    }
  }
  const seen = new Set<string>();
  const queue = [...roots];
  while (queue.length > 0) {
    const current = queue.pop();
    if (current === undefined || seen.has(current)) {continue;}
    seen.add(current);
    const parents = reverse.get(current) ?? [];
    for (const parent of parents) {queue.push(parent);}
  }
  return [...seen].sort();
}

async function fileMtimes(cwd: string): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (const file of await walkFiles({ cwd })) {
    try {
      out.set(file, (await stat(join(cwd, file))).mtimeMs);
    } catch {
      // gone between the walk and the stat
    }
  }
  return out;
}

function mtimeDelta(prev: ReadonlyMap<string, number>, next: ReadonlyMap<string, number>): string[] {
  const changed: string[] = [];
  for (const [file, mtime] of next) {
    if (prev.get(file) !== mtime) {changed.push(file);}
  }
  for (const file of prev.keys()) {
    if (!next.has(file)) {changed.push(file);}
  }
  return changed;
}

async function readSources(cwd: string, files: readonly string[]): Promise<Map<string, string>> {
  const sources = new Map<string, string>();
  for (const file of files) {
    if (!SOURCE.test(file)) {continue;}
    try {
      sources.set(file, await readFile(join(cwd, file), 'utf8'));
    } catch {
      sources.set(file, '');
    }
  }
  return sources;
}

async function expandChanged(cwd: string, changed: readonly string[]): Promise<string[]> {
  const files = await walkFiles({ cwd });
  const sources = await readSources(cwd, files);
  const sourceRoots = changed.filter((file) => SOURCE.test(file) && sources.has(file));
  const deleted = changed.filter((file) => SOURCE.test(file) && !sources.has(file));
  const other = changed.filter((file) => !SOURCE.test(file));
  return [...new Set([...reverseClosure(sources, sourceRoots), ...deleted, ...other])].sort();
}

function replaced(finding: Finding, rescanned: ReadonlySet<string>, deps: boolean): boolean {
  const file = (finding.file ?? '').replace(/\\/g, '/');
  if (file.length > 0) {return rescanned.has(file);}
  return deps && finding.module === 'deps';
}

function mergeFindings(previous: readonly Finding[], partial: readonly Finding[], rescanned: ReadonlySet<string>, deps: boolean): Finding[] {
  const kept = previous.filter((finding) => !replaced(finding, rescanned, deps));
  const fresh = partial.filter((finding) => replaced(finding, rescanned, deps));
  return [...kept, ...fresh];
}

function changeLines(previous: readonly Finding[], next: readonly Finding[]): string[] {
  const prev = new Map(previous.map((finding) => [lineIndependentFingerprint(finding), finding]));
  const curr = new Map(next.map((finding) => [lineIndependentFingerprint(finding), finding]));
  const lines: string[] = [];
  for (const [key, finding] of curr) {
    if (!prev.has(key)) {lines.push(formatLine('new', finding));}
  }
  for (const [key, finding] of prev) {
    if (!curr.has(key)) {lines.push(formatLine('resolved', finding));}
  }
  return lines.sort((a, b) => a.localeCompare(b));
}

function formatLine(kind: 'new' | 'resolved', finding: Finding): string {
  const file = (finding.file ?? '').replace(/\\/g, '/');
  return file.length === 0 ? `${kind} ${finding.ruleId}` : `${kind} ${finding.ruleId} ${file}`;
}

async function scanChanged(cwd: string, changed: readonly string[] | undefined): Promise<Finding[]> {
  const deps = changed === undefined || changed.some((file) => isManifest(file));
  const modules: ModuleName[] | undefined = deps ? undefined : ['secrets', 'sast', 'config'];
  const result = await scan({
    cwd,
    modules,
    experimentalIncremental: changed !== undefined,
    changedFiles: changed === undefined ? undefined : [...changed],
  });
  return result.findings;
}

async function applyBatch(state: LoopState, hinted: readonly string[]): Promise<void> {
  if (state.closed) {return;}
  const nextTimes = await fileMtimes(state.cwd);
  const discovered = [...new Set([...hinted, ...mtimeDelta(state.mtimes, nextTimes)])].filter((file) => !skipPath(file));
  state.mtimes = nextTimes;
  if (discovered.length === 0 || state.closed) {return;}
  const rescanned = await expandChanged(state.cwd, discovered);
  const partial = await scanChanged(state.cwd, rescanned);
  if (state.closed) {return;}
  const deps = discovered.some((file) => isManifest(file));
  const merged = mergeFindings(state.previous, partial, new Set(rescanned), deps);
  for (const line of changeLines(state.previous, merged)) {state.out(line);}
  state.previous = merged;
}

function createDebounce(onFlush: (paths: string[]) => void): { push(rel: string | undefined): void; cancel(): void } {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pending = new Set<string>();
  let unknown = false;
  return {
    push(rel) {
      if (rel === undefined) {unknown = true;}
      else {notePath(pending, rel);}
      if (timer !== undefined) {clearTimeout(timer);}
      timer = setTimeout(() => {
        timer = undefined;
        const batch = [...pending];
        const flush = unknown || batch.length > 0;
        pending.clear();
        unknown = false;
        if (flush) {onFlush(batch);}
      }, DEBOUNCE_MS);
    },
    cancel() {
      if (timer !== undefined) {clearTimeout(timer);}
      timer = undefined;
      pending.clear();
      unknown = false;
    },
  };
}

function notePath(pending: Set<string>, rel: string): void {
  const posix = toPosix(rel);
  if (!skipPath(posix) && posix.length > 0) {pending.add(posix);}
}

function openPoll(cwd: string, interval: number, onPath: (rel: string) => void, initial: Map<string, number>): Stoppable {
  let current = initial;
  let stopped = false;
  const timer = setInterval(() => {
    void pollOnce();
  }, interval);

  async function pollOnce(): Promise<void> {
    if (stopped) {return;}
    const next = await fileMtimes(cwd);
    if (stopped) {return;}
    const delta = mtimeDelta(current, next);
    current = next;
    for (const file of delta) {onPath(file);}
  }

  return {
    close() {
      stopped = true;
      clearInterval(timer);
    },
  };
}

function openRecursive(cwd: string, onPath: (rel: string | undefined) => void): Stoppable | undefined {
  try {
    const watcher = watch(cwd, { recursive: true }, (_event, filename) => {
      onPath(filename === null ? undefined : filename.toString());
    });
    return {
      close() {
        watcher.close();
      },
    };
  } catch {
    return undefined;
  }
}

function openWatcher(cwd: string, platform: NodeJS.Platform, interval: number, mtimes: Map<string, number>, onPath: (rel: string | undefined) => void): Stoppable {
  const poll = openPoll(cwd, interval, (rel) => onPath(rel), mtimes);
  if (!recursiveWatch(platform)) {return poll;}
  const watcher = openRecursive(cwd, onPath);
  if (watcher === undefined) {return poll;}
  return {
    close() {
      watcher.close();
      poll.close();
    },
  };
}

function bindStop(close: () => void): () => void {
  const onSignal = (): void => {
    close();
  };
  process.on('SIGINT', onSignal);
  return () => {
    process.off('SIGINT', onSignal);
  };
}

function arm(state: LoopState, platform: NodeJS.Platform, interval: number, onClose: () => void): Stoppable {
  let chain: Promise<void> = Promise.resolve();
  const debounce = createDebounce((paths) => {
    chain = chain.then(() => applyBatch(state, paths)).then(() => undefined, () => undefined);
  });
  const watcher = openWatcher(state.cwd, platform, interval, state.mtimes, (rel) => debounce.push(rel));
  let unbind = (): void => undefined;
  const close = (): void => {
    if (state.closed) {return;}
    state.closed = true;
    debounce.cancel();
    watcher.close();
    closeAllDbHandles();
    unbind();
    onClose();
  };
  unbind = bindStop(close);
  return { close };
}

async function initialState(cwd: string, out: (line: string) => void): Promise<LoopState> {
  return {
    cwd,
    out,
    previous: await scanChanged(cwd, undefined),
    mtimes: await fileMtimes(cwd),
    closed: false,
  };
}

/** Watch the project and print findings that appeared or disappeared. */
export async function startDevLoop(options: DevOptions): Promise<DevSession> {
  if (!devEnabled()) {throw new DevError(`dev requires ${DEV_FLAG}=1`);}
  const cwd = resolve(options.cwd);
  const state = await initialState(cwd, options.out);
  let resolveDone: () => void = () => undefined;
  const done = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });
  const watcher = arm(state, options.platform ?? process.platform, pollMs(options.pollIntervalMs), () => {
    resolveDone();
  });
  return {
    done,
    close(): Promise<void> {
      watcher.close();
      return Promise.resolve();
    },
  };
}
