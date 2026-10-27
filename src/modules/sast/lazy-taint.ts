import { posix } from 'node:path';

/** Express/Fastify-style request reads, argv, and destructured handlers. */
const CLASSIC_SOURCE_RE =
  /\breq\s*(?:\.|\[)\s*['"]?(?:query|body|params|headers|files|cookies)\b|\bprocess\s*(?:\.|\[)\s*['"]?argv\b|\(\s*\{[^)]*\b(?:query|body|params|headers|files)\b/;

/**
 * Framework sources that taint analysis recognizes (Next/Nest/Hono/Koa) but that
 * do not look like classic `req.query` text. Skipping these drops real findings.
 */
const FRAMEWORK_SOURCE_RE =
  /\brequest\s*\.\s*(?:json|formData|text|arrayBuffer)\s*\(|\brequest\s*\.\s*nextUrl\b|\bsearchParams\b|\bformData\s*\.\s*get\s*\(|@(?:Body|Query|Param|Headers)\b|\bc\.req\s*\.|\bctx\.(?:query|params|request)\b/;

/** Facts besides request taint that still come from the taint walk. */
const KEEP_RE =
  /\b(?:password|passwd|createHash|pbkdf2|scrypt|argon2|rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|checkServerIdentity)\b/i;

const MAX_IMPORT_DEPTH = 5;

let lastWalk: string[] | undefined;

export function clearTaintWalk(): void {
  lastWalk = undefined;
}

export function takeLastTaintWalk(): readonly string[] | undefined {
  return lastWalk;
}

export function fileNeedsTaintWalk(source: string): boolean {
  return CLASSIC_SOURCE_RE.test(source) || FRAMEWORK_SOURCE_RE.test(source) || KEEP_RE.test(source);
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
 * Files that contain a source, plus files on an import path (either direction)
 * up to depth 5. Outward covers helpers a source imports; inward covers callers
 * that use a returning helper. Targets `walkScope` / `inner` from the profile.
 */
export function lazyTaintFiles(entries: readonly { file: string; source: string }[]): Set<string> {
  const files = new Set(entries.map((entry) => entry.file));
  const imports = new Map<string, Set<string>>();
  const importers = new Map<string, Set<string>>();
  const seeds: string[] = [];
  for (const entry of entries) {
    if (fileNeedsTaintWalk(entry.source)) {seeds.push(entry.file);}
    const deps = importsOf(entry.file, entry.source, files);
    imports.set(entry.file, deps);
    for (const dep of deps) {
      const parents = importers.get(dep) ?? new Set<string>();
      parents.add(entry.file);
      importers.set(dep, parents);
    }
  }
  const walked = new Set<string>(seeds);
  const queue = seeds.map((file) => ({ file, depth: 0 }));
  while (queue.length > 0) {
    const item = queue.shift();
    if (item === undefined || item.depth >= MAX_IMPORT_DEPTH) {continue;}
    const neighbors = [...(imports.get(item.file) ?? []), ...(importers.get(item.file) ?? [])];
    for (const dep of neighbors) {
      if (walked.has(dep)) {continue;}
      walked.add(dep);
      queue.push({ file: dep, depth: item.depth + 1 });
    }
  }
  lastWalk = [...walked].sort();
  return walked;
}
