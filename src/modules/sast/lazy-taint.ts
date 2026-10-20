import { posix } from 'node:path';

const SOURCE_RE =
  /\breq\s*(?:\.|\[)\s*['"]?(?:query|body|params|headers|files|cookies)\b|\bprocess\s*(?:\.|\[)\s*['"]?argv\b|\(\s*\{[^)]*\b(?:query|body|params|headers|files)\b/;

/** Facts besides request taint that still come from the taint walk. */
const KEEP_RE = /\b(?:password|passwd|createHash|pbkdf2|scrypt|argon2)\b/i;

const MAX_IMPORT_DEPTH = 5;

let lastWalk: string[] | undefined;

export function clearTaintWalk(): void {
  lastWalk = undefined;
}

export function takeLastTaintWalk(): readonly string[] | undefined {
  return lastWalk;
}

export function fileNeedsTaintWalk(source: string): boolean {
  return SOURCE_RE.test(source) || KEEP_RE.test(source);
}

const IMPORT_RE = /(?:require\(\s*|from\s*)['"](\.[^'"]+)['"]/g;

function resolveSpec(fromFile: string, spec: string, files: ReadonlySet<string>): string | undefined {
  if (!spec.startsWith('.')) {return undefined;}
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec));
  const candidates = [
    base,
    `${base}.js`,
    `${base}.ts`,
    `${base}.mjs`,
    `${base}.cjs`,
    `${base}/index.js`,
    `${base}/index.ts`,
  ];
  return candidates.find((candidate) => files.has(candidate));
}

function importsOf(file: string, source: string, files: ReadonlySet<string>): Set<string> {
  const deps = new Set<string>();
  IMPORT_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IMPORT_RE.exec(source)) !== null) {
    const spec = match[1];
    if (spec === undefined) {continue;}
    const resolved = resolveSpec(file, spec, files);
    if (resolved !== undefined) {deps.add(resolved);}
  }
  return deps;
}

/**
 * Files that contain a source, plus files they import up to depth 5.
 * Targets `walkScope` / `inner` from the step 1 profile.
 */
export function lazyTaintFiles(entries: readonly { file: string; source: string }[]): Set<string> {
  const files = new Set(entries.map((entry) => entry.file));
  const imports = new Map<string, Set<string>>();
  const seeds: string[] = [];
  for (const entry of entries) {
    if (fileNeedsTaintWalk(entry.source)) {seeds.push(entry.file);}
    imports.set(entry.file, importsOf(entry.file, entry.source, files));
  }
  const walked = new Set<string>(seeds);
  const queue = seeds.map((file) => ({ file, depth: 0 }));
  while (queue.length > 0) {
    const item = queue.shift();
    if (item === undefined || item.depth >= MAX_IMPORT_DEPTH) {continue;}
    for (const dep of imports.get(item.file) ?? []) {
      if (walked.has(dep)) {continue;}
      walked.add(dep);
      queue.push({ file: dep, depth: item.depth + 1 });
    }
  }
  lastWalk = [...walked].sort();
  return walked;
}
