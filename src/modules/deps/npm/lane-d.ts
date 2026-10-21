import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding, Severity } from '../../../core/finding.js';
import { npmFinding, npmFlag, npmRow, type NpmDepthInput, type NpmDepthRow } from './types.js';

/** Phases 168–187. Direct production tarballs only. Cache only: this lane never fetches. */

const HASH = npmRow('DEPS-TARBALL-HASH-001', 'CWE-353');
const ID = npmRow('DEPS-TARBALL-ID-001', 'CWE-494');
const LIFECYCLE = npmRow('DEPS-TARBALL-LIFECYCLE-001', 'CWE-829');
const NET = npmRow('DEPS-TARBALL-NET-001', 'CWE-829');
const SHELL = npmRow('DEPS-TARBALL-SHELL-001', 'CWE-78');
const CRED = npmRow('DEPS-TARBALL-CRED-001', 'CWE-522');
const OBFUSC = npmRow('DEPS-TARBALL-OBFUSC-001', 'CWE-506');
const BIN = npmRow('DEPS-TARBALL-BIN-001', 'CWE-427');
const NATIVE = npmRow('DEPS-TARBALL-NATIVE-001', 'CWE-829');
const HOOK = npmRow('DEPS-TARBALL-HOOK-001', 'CWE-829');
const HIDDEN = npmRow('DEPS-TARBALL-HIDDEN-001', 'CWE-451');
const PATH = npmRow('DEPS-TARBALL-PATH-001', 'CWE-22');
const SIZE = npmRow('DEPS-TARBALL-SIZE-001', 'CWE-770');
const LICENSE = npmRow('DEPS-TARBALL-LICENSE-001', 'CWE-1104');
const MANIFEST = npmRow('DEPS-TARBALL-MANIFEST-001', 'CWE-494');
const INSTALLJS = npmRow('DEPS-TARBALL-INSTALLJS-001', 'CWE-829');
const TOPLEVEL = npmRow('DEPS-TARBALL-TOPLEVEL-001', 'CWE-829');
const ENV = npmRow('DEPS-TARBALL-ENV-001', 'CWE-200');
const DYNAMIC = npmRow('DEPS-TARBALL-DYNAMIC-001', 'CWE-829');
const SKIP = npmRow('DEPS-TARBALL-SKIP-001', 'CWE-353');

export const laneRows: readonly NpmDepthRow[] = [
  HASH,
  ID,
  LIFECYCLE,
  NET,
  SHELL,
  CRED,
  OBFUSC,
  BIN,
  NATIVE,
  HOOK,
  HIDDEN,
  PATH,
  SIZE,
  LICENSE,
  MANIFEST,
  INSTALLJS,
  TOPLEVEL,
  ENV,
  DYNAMIC,
  SKIP,
];

const META: Record<string, { severity: Severity; title: string; remediation: string }> = {
  [HASH.ruleId]: {
    severity: 'critical',
    title: 'Tarball hash does not match dist.integrity',
    remediation: 'Replace the cached tarball with the registry.npmjs.org artifact that matches the lock integrity.',
  },
  [ID.ruleId]: {
    severity: 'critical',
    title: 'Tarball package identity does not match the lock',
    remediation: 'Do not install this tarball. The archive package.json name or version is not the locked package.',
  },
  [LIFECYCLE.ruleId]: {
    severity: 'high',
    title: 'Tarball lifecycle script hidden by the packument',
    remediation: 'Treat the package as untrusted. The tarball runs an install script the packument marked absent.',
  },
  [NET.ruleId]: {
    severity: 'high',
    title: 'Lifecycle script contacts the network',
    remediation: 'Remove the install script or pin a release whose lifecycle script does not fetch remote code.',
  },
  [SHELL.ruleId]: {
    severity: 'high',
    title: 'Lifecycle script invokes a shell or downloader',
    remediation: 'Remove curl, wget, bash, powershell, or child_process from the install script.',
  },
  [CRED.ruleId]: {
    severity: 'critical',
    title: 'Lifecycle script reads credentials',
    remediation: 'Do not install this package. The install script references credential files or tokens.',
  },
  [OBFUSC.ruleId]: {
    severity: 'high',
    title: 'Lifecycle script passes base64 to eval or spawn',
    remediation: 'Do not install this package. The install script decodes a long base64 literal into eval, Function, or spawn.',
  },
  [BIN.ruleId]: {
    severity: 'medium',
    title: 'package.json bin target is not in the tarball',
    remediation: 'Point bin at a file that exists inside the package, or remove the bin entry.',
  },
  [NATIVE.ruleId]: {
    severity: 'medium',
    title: 'Tarball contains a prebuilt native binary',
    remediation: 'Review the package. A prebuilt binary could not be reviewed as source.',
  },
  [HOOK.ruleId]: {
    severity: 'critical',
    title: 'Tarball contains a git hook or GitHub workflow',
    remediation: 'Do not install this package. A dependency archive should not ship hook or workflow files.',
  },
  [HIDDEN.ruleId]: {
    severity: 'medium',
    title: 'Tarball path is hidden or uses a bidi override',
    remediation: 'Reject the archive. A path segment hides its name with a dot and a non-latin letter, or a bidi override.',
  },
  [PATH.ruleId]: {
    severity: 'critical',
    title: 'Tarball entry escapes the package directory',
    remediation: 'Do not extract this entry. Absolute paths and .. segments are skipped.',
  },
  [SIZE.ruleId]: {
    severity: 'info',
    title: 'Tarball exceeds the unpack cap',
    remediation: 'The cap is a limit, not a vulnerability count. Inspect the package before raising it.',
  },
  [LICENSE.ruleId]: {
    severity: 'info',
    title: 'Tarball license string differs from the packument',
    remediation: 'Compare the two license strings. This finding does not judge which license is acceptable.',
  },
  [MANIFEST.ruleId]: {
    severity: 'high',
    title: 'Tarball dependencies differ from the packument',
    remediation: 'Treat the tarball as a swapped manifest. Name and version mismatches are a separate finding.',
  },
  [INSTALLJS.ruleId]: {
    severity: 'medium',
    title: 'Loose install.js without a lifecycle script key',
    remediation: 'Remove package/install.js, preinstall.js, or postinstall.js, or declare the matching scripts key.',
  },
  [TOPLEVEL.ruleId]: {
    severity: 'high',
    title: 'Package entry calls the network or child_process at top level',
    remediation: 'Move fetch, http.request, https.request, and child_process calls inside a function.',
  },
  [ENV.ruleId]: {
    severity: 'critical',
    title: 'Package entry sends process.env to the network',
    remediation: 'Do not pass the process.env object to fetch, http.request, or https.request.',
  },
  [DYNAMIC.ruleId]: {
    severity: 'medium',
    title: 'Package entry dynamically loads a module at top level',
    remediation: 'Use a string literal require or import, or move the dynamic call inside a function.',
  },
  [SKIP.ruleId]: {
    severity: 'info',
    title: 'Direct dependency tarball refused for missing integrity',
    remediation: 'Add a sha512 integrity to the lock entry before fetching its tarball. Transitive tarballs are not downloaded.',
  },
};

const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall'] as const;
const SIZE_CAP = 20 * 1024 * 1024;
const COUNT_CAP = 2000;
const NET_TOKENS = ['http://', 'https://', 'fetch(', 'dns'];
const SHELL_TOKENS = ['curl', 'wget', 'bash', 'sh -c', 'powershell', 'child_process'];
const CRED_TOKENS = ['.npmrc', '.ssh', '.aws', '.git-credentials', 'NPM_TOKEN', 'NODE_AUTH_TOKEN', 'npm_config__auth'];
const HIDDEN_ALLOW = new Set(['.npmignore', '.gitignore', '.github']);
const BIDI = /[\u202A-\u202E\u2066-\u2069]/u;

interface DirectDep {
  name: string;
  version: string;
  integrity?: string;
  resolved?: string;
  lockFile: string;
}

interface VersionDoc {
  hasInstallScript?: unknown;
  license?: unknown;
  dependencies?: unknown;
  dist?: { integrity?: unknown; tarball?: unknown };
}

interface Parsed {
  type: string;
  parent?: Parsed;
  callee?: unknown;
  arguments?: unknown;
  source?: unknown;
  object?: unknown;
  property?: unknown;
  computed?: unknown;
  name?: unknown;
  value?: unknown;
  quasis?: unknown;
  expressions?: unknown;
  [key: string]: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

function isParsed(value: unknown): value is Parsed {
  return isRecord(value) && typeof value.type === 'string';
}

function textField(obj: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = obj?.[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function objectKeys(value: unknown): string[] {
  const record = asRecord(value);
  return record === undefined ? [] : Object.keys(record);
}

function anyFlag(): boolean {
  return laneRows.some((row) => {
    const flag = row.ruleId.replace('DEPS-TARBALL-', 'NPM_TARBALL_').replace(/-001$/, '');
    if (row.ruleId === SKIP.ruleId) {return npmFlag('NPM_TARBALL_GATE');}
    return npmFlag(flag);
  });
}

function flagFor(row: NpmDepthRow): boolean {
  if (row.ruleId === SKIP.ruleId) {return npmFlag('NPM_TARBALL_GATE');}
  const flag = row.ruleId.replace('DEPS-TARBALL-', 'NPM_TARBALL_').replace(/-001$/, '');
  return npmFlag(flag);
}

function pickLock(input: NpmDepthInput): { file: string; text: string } | undefined {
  if (input.lockTexts['package-lock.json'] !== undefined) {
    return { file: 'package-lock.json', text: input.lockTexts['package-lock.json'] };
  }
  if (input.lockTexts['npm-shrinkwrap.json'] !== undefined) {
    return { file: 'npm-shrinkwrap.json', text: input.lockTexts['npm-shrinkwrap.json'] };
  }
  return undefined;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function directProd(lockText: string, manifestRaw: string | undefined, lockFile: string): DirectDep[] {
  const lock = asRecord(parseJson(lockText));
  if (lock === undefined) {return [];}
  const manifest = manifestRaw === undefined ? undefined : asRecord(parseJson(manifestRaw));
  const packages = asRecord(lock.packages);
  const root = packages === undefined ? undefined : asRecord(packages['']);
  const prod = new Set<string>([
    ...objectKeys(root?.dependencies),
    ...objectKeys(manifest?.dependencies),
  ]);
  const out: DirectDep[] = [];
  if (packages !== undefined) {
    for (const name of prod) {
      const entry = asRecord(packages[`node_modules/${name}`]);
      const version = textField(entry, 'version');
      if (entry === undefined || version === undefined) {continue;}
      out.push({
        name,
        version,
        integrity: textField(entry, 'integrity'),
        resolved: textField(entry, 'resolved'),
        lockFile,
      });
    }
    return out;
  }
  const tree = asRecord(lock.dependencies);
  if (tree === undefined) {return [];}
  const manifestProd = manifest === undefined ? undefined : new Set(objectKeys(manifest.dependencies));
  for (const [name, value] of Object.entries(tree)) {
    if (manifestProd !== undefined && !manifestProd.has(name)) {continue;}
    const entry = asRecord(value);
    const version = textField(entry, 'version');
    if (entry === undefined || version === undefined) {continue;}
    if (entry.dev === true || entry.optional === true) {continue;}
    out.push({
      name,
      version,
      integrity: textField(entry, 'integrity'),
      resolved: textField(entry, 'resolved'),
      lockFile,
    });
  }
  return out;
}

function isRegistryUrl(url: string | undefined): boolean {
  if (url === undefined) {return false;}
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' && parsed.hostname === 'registry.npmjs.org';
  } catch {
    return false;
  }
}

/** A present URL that is not an https registry.npmjs.org tarball blocks this package. */
function urlBlocks(url: string | undefined): boolean {
  if (url === undefined || url.length === 0) {return false;}
  if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) {return false;}
  return !isRegistryUrl(url);
}

async function readJson(path: string): Promise<unknown> {
  try {
    return parseJson(await readFile(path, 'utf8'));
  } catch {
    return undefined;
  }
}

async function readVersion(cacheDir: string, name: string, version: string): Promise<VersionDoc | undefined> {
  const paths = [
    join(cacheDir, 'registry', `${name}.json`),
    join(cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`),
    join(cacheDir, 'registry', `${encodeURIComponent(name)}.json`),
  ];
  for (const path of paths) {
    const doc = asRecord(await readJson(path));
    const packument = asRecord(doc?.packument) ?? doc;
    const versions = asRecord(packument?.versions);
    const entry = asRecord(versions?.[version]);
    if (entry !== undefined) {return entry;}
  }
  return undefined;
}

function integrityFile(integrity: string): string {
  return `${integrity.replaceAll('/', '_').replaceAll('+', '_')}.tar`;
}

function sha512Token(bytes: Buffer): string {
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}

function integrityMatches(expected: string, bytes: Buffer): boolean {
  const actual = sha512Token(bytes);
  return expected.split(/\s+/).some((token) => token === actual);
}

interface Loaded {
  bytes?: Buffer;
  entries: Record<string, string>;
}

async function loadDescriptor(cacheDir: string, name: string): Promise<Loaded | undefined> {
  const paths = [
    join(cacheDir, 'tarballs', `${name}.json`),
    join(cacheDir, 'tarballs', `${name.replaceAll('/', '%2f')}.json`),
  ];
  for (const path of paths) {
    const doc = asRecord(await readJson(path));
    if (doc === undefined) {continue;}
    const loaded: Loaded = { entries: {} };
    if (typeof doc.bytesBase64 === 'string' && doc.bytesBase64.length > 0) {
      loaded.bytes = Buffer.from(doc.bytesBase64, 'base64');
    }
    const entries = asRecord(doc.entries);
    if (entries !== undefined) {
      for (const [key, value] of Object.entries(entries)) {
        if (typeof value === 'string') {loaded.entries[key] = value;}
      }
    }
    return loaded;
  }
  return undefined;
}

async function loadIntegrityFile(cacheDir: string, integrity: string): Promise<Buffer | undefined> {
  try {
    return await readFile(join(cacheDir, 'tarballs', integrityFile(integrity)));
  } catch {
    return undefined;
  }
}

function parseUstar(buf: Buffer): Record<string, string> {
  const entries: Record<string, string> = {};
  let offset = 0;
  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {break;}
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/u, '');
    const full = prefix.length > 0 ? `${prefix}/${name}` : name;
    const sizeText = header.subarray(124, 136).toString('utf8').replace(/\0.*$/u, '').trim();
    const size = Number.parseInt(sizeText, 8);
    const typeflag = header[156] ?? 0;
    offset += 512;
    const bytes = Number.isFinite(size) && size > 0 ? size : 0;
    const data = buf.subarray(offset, offset + bytes);
    offset += bytes;
    if (bytes % 512 !== 0) {offset += 512 - (bytes % 512);}
    if (full.length > 0 && (typeflag === 0 || typeflag === 48)) {
      entries[full] = data.toString('utf8');
    }
  }
  return entries;
}

function normalizeSeparators(name: string): string {
  return name.replaceAll('\\', '/');
}

function isEscape(name: string): boolean {
  const norm = normalizeSeparators(name);
  if (norm.startsWith('/') || /^[A-Za-z]:/u.test(norm)) {return true;}
  return norm.split('/').includes('..');
}

function hasNonLatinLetter(segment: string): boolean {
  for (const ch of segment) {
    if (/\p{L}/u.test(ch) && !/\p{Script=Latin}/u.test(ch)) {return true;}
  }
  return false;
}

function hiddenSegment(segment: string): boolean {
  if (BIDI.test(segment)) {return true;}
  if (HIDDEN_ALLOW.has(segment)) {return false;}
  return segment.startsWith('.') && hasNonLatinLetter(segment);
}

function scriptMap(pkg: Record<string, unknown>): Record<string, string> {
  const scripts = asRecord(pkg.scripts);
  if (scripts === undefined) {return {};}
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(scripts)) {
    if (typeof value === 'string') {out[key] = value;}
  }
  return out;
}

function lifecycleScripts(scripts: Record<string, string>): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const key of LIFECYCLE_KEYS) {
    const value = scripts[key];
    if (value !== undefined) {out.push([key, value]);}
  }
  return out;
}

function containsToken(text: string, tokens: readonly string[]): boolean {
  return tokens.some((token) => text.includes(token));
}

function hasObfuscatedEval(script: string): boolean {
  const spans: Array<[number, number]> = [];
  for (const name of ['eval', 'Function', 'spawn']) {
    const re = new RegExp(`\\b${name}\\s*\\(`, 'g');
    for (const match of script.matchAll(re)) {
      const token = match[0];
      if (token === undefined) {continue;}
      const start = match.index ?? 0;
      const open = start + token.length;
      let depth = 1;
      let i = open;
      for (; i < script.length && depth > 0; i += 1) {
        const ch = script[i];
        if (ch === '(') {depth += 1;}
        else if (ch === ')') {depth -= 1;}
      }
      spans.push([open, i]);
    }
  }
  if (spans.length === 0) {return false;}
  for (const match of script.matchAll(/['"]([A-Za-z0-9+/]{32,}={0,2})['"]/g)) {
    const index = match.index ?? 0;
    if (spans.some(([start, end]) => index >= start && index < end)) {return true;}
  }
  return false;
}

function stringMap(value: unknown): Record<string, string> | undefined {
  const record = asRecord(value);
  if (record === undefined) {return undefined;}
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(record)) {
    if (typeof item === 'string') {out[key] = item;}
    else {return undefined;}
  }
  return out;
}

function sameDeps(left: Record<string, string>, right: Record<string, string>): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) {return false;}
  return leftKeys.every((key, index) => key === rightKeys[index] && left[key] === right[key]);
}

function binPaths(bin: unknown): string[] {
  if (typeof bin === 'string' && bin.length > 0) {return [bin];}
  const record = asRecord(bin);
  if (record === undefined) {return [];}
  return Object.values(record).filter((value): value is string => typeof value === 'string' && value.length > 0);
}

function entryCandidates(spec: string): string[] {
  const norm = normalizeSeparators(spec).replace(/^\.\//u, '');
  const prefixed = norm.startsWith('package/') ? norm : `package/${norm}`;
  return [...new Set([norm, prefixed])];
}

function hasFile(names: ReadonlySet<string>, spec: string): boolean {
  return entryCandidates(spec).some((candidate) => names.has(candidate));
}

function fileText(entries: Record<string, string>, spec: string): string | undefined {
  for (const candidate of entryCandidates(spec)) {
    const text = entries[candidate];
    if (text !== undefined) {return text;}
  }
  return undefined;
}

function collectExportFiles(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    if (value.startsWith('.') || value.includes('/')) {out.push(value);}
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {collectExportFiles(item, out);}
    return;
  }
  const record = asRecord(value);
  if (record === undefined) {return;}
  for (const item of Object.values(record)) {collectExportFiles(item, out);}
}

function entrySpecs(pkg: Record<string, unknown>): string[] {
  const specs: string[] = [];
  if (typeof pkg.main === 'string' && pkg.main.length > 0) {specs.push(pkg.main);}
  collectExportFiles(pkg.exports, specs);
  return [...new Set(specs)];
}

function report(findings: Finding[], row: NpmDepthRow, file: string, snippet: string, message: string): void {
  const meta = META[row.ruleId];
  if (meta === undefined) {return;}
  const key = `${row.ruleId}\0${file}\0${snippet}`;
  if (findings.some((finding) => `${finding.ruleId}\0${finding.file ?? ''}\0${finding.snippet ?? ''}` === key)) {return;}
  findings.push(npmFinding(row.ruleId, meta.severity, file, snippet, meta.title, message, meta.remediation));
}

const WALK_SKIP = new Set(['parent', 'loc', 'range', 'type']);

function attachParents(node: Parsed, parent?: Parsed): void {
  if (parent !== undefined) {node.parent = parent;}
  for (const key of Object.keys(node)) {
    if (WALK_SKIP.has(key)) {continue;}
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (isParsed(child)) {attachParents(child, node);}
      }
    } else if (isParsed(value)) {attachParents(value, node);}
  }
}

function walk(node: Parsed, visit: (current: Parsed) => void): void {
  visit(node);
  for (const key of Object.keys(node)) {
    if (WALK_SKIP.has(key)) {continue;}
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (isParsed(child)) {walk(child, visit);}
      }
    } else if (isParsed(value)) {walk(value, visit);}
  }
}

async function parseCode(code: string): Promise<Parsed | undefined> {
  try {
    const { parseSource } = await import('../../sast/engine.js');
    const ast: unknown = await parseSource(code);
    if (!isParsed(ast)) {return undefined;}
    attachParents(ast);
    return ast;
  } catch {
    return undefined;
  }
}

function childParsed(value: unknown): Parsed | undefined {
  return isParsed(value) ? value : undefined;
}

function propName(node: Parsed): string | undefined {
  const property = childParsed(node.property);
  if (property === undefined || node.computed === true) {return undefined;}
  if (property.type === 'Identifier' && typeof property.name === 'string') {return property.name;}
  if (property.type === 'Literal' && typeof property.value === 'string') {return property.value;}
  return undefined;
}

function calleeName(node: Parsed): string | undefined {
  const callee = childParsed(node.callee);
  if (callee === undefined) {return undefined;}
  if (callee.type === 'Identifier' && typeof callee.name === 'string') {return callee.name;}
  if (callee.type === 'MemberExpression') {return propName(callee);}
  return undefined;
}

function literalString(node: Parsed | undefined): string | undefined {
  if (node === undefined) {return undefined;}
  if (node.type === 'Literal' && typeof node.value === 'string') {return node.value;}
  if (node.type === 'TemplateLiteral' && Array.isArray(node.expressions) && node.expressions.length === 0) {
    const quasis = Array.isArray(node.quasis) ? node.quasis : [];
    const first = asRecord(quasis[0]);
    const cooked = asRecord(first?.value);
    if (typeof cooked?.cooked === 'string') {return cooked.cooked;}
    if (typeof cooked?.raw === 'string') {return cooked.raw;}
  }
  return undefined;
}

function insideFunction(node: Parsed): boolean {
  let current = node.parent;
  while (current !== undefined) {
    if (
      current.type === 'FunctionDeclaration' ||
      current.type === 'FunctionExpression' ||
      current.type === 'ArrowFunctionExpression'
    ) {return true;}
    current = current.parent;
  }
  return false;
}

function isHttpRequest(node: Parsed): boolean {
  const callee = childParsed(node.callee);
  if (callee === undefined || callee.type !== 'MemberExpression') {return false;}
  if (propName(callee) !== 'request') {return false;}
  const object = childParsed(callee.object);
  return object?.type === 'Identifier' && (object.name === 'http' || object.name === 'https');
}

function isChildProcessCall(node: Parsed): boolean {
  const callee = childParsed(node.callee);
  if (callee === undefined || callee.type !== 'MemberExpression') {return false;}
  const object = childParsed(callee.object);
  if (object === undefined) {return false;}
  if (object.type === 'Identifier' && object.name === 'child_process') {return true;}
  if (object.type === 'CallExpression' && calleeName(object) === 'require') {
    const args = Array.isArray(object.arguments) ? object.arguments : [];
    return literalString(childParsed(args[0])) === 'child_process';
  }
  return false;
}

function isTopLevelSink(node: Parsed): boolean {
  return calleeName(node) === 'fetch' || isHttpRequest(node) || isChildProcessCall(node);
}

function isExfilCall(node: Parsed): boolean {
  return calleeName(node) === 'fetch' || isHttpRequest(node);
}

function isWholeEnv(node: Parsed): boolean {
  if (node.type !== 'MemberExpression') {return false;}
  const object = childParsed(node.object);
  return object?.type === 'Identifier' && object.name === 'process' && propName(node) === 'env';
}

function passesWholeEnv(root: Parsed): boolean {
  let hit = false;
  walk(root, (node) => {
    if (!isWholeEnv(node)) {return;}
    const parent = node.parent;
    if (parent?.type === 'MemberExpression' && parent.object === node) {return;}
    hit = true;
  });
  return hit;
}

function callArgs(node: Parsed): Parsed[] {
  if (!Array.isArray(node.arguments)) {return [];}
  return node.arguments.filter(isParsed);
}

function isDynamicLoad(node: Parsed): boolean {
  if (node.type === 'ImportExpression') {
    return literalString(childParsed(node.source)) === undefined;
  }
  if (node.type === 'CallExpression' && calleeName(node) === 'require') {
    return literalString(callArgs(node)[0]) === undefined;
  }
  return false;
}

async function scanEntryFile(
  findings: Finding[],
  dep: DirectDep,
  spec: string,
  text: string,
): Promise<void> {
  const ast = await parseCode(text);
  if (ast === undefined) {return;}
  let top = false;
  let env = false;
  let dynamic = false;
  walk(ast, (node) => {
    if (node.type === 'CallExpression' && !insideFunction(node) && isTopLevelSink(node)) {top = true;}
    if ((node.type === 'CallExpression' || node.type === 'ImportExpression') && isExfilCall(node)) {
      if (callArgs(node).some((arg) => passesWholeEnv(arg))) {env = true;}
    }
    if (!insideFunction(node) && isDynamicLoad(node)) {dynamic = true;}
  });
  const snippet = `${dep.name}@${dep.version} ${spec}`;
  if (top && flagFor(TOPLEVEL)) {
    report(findings, TOPLEVEL, dep.lockFile, snippet, `${dep.name}@${dep.version} calls fetch, http.request, https.request, or child_process outside a function in ${spec}.`);
  }
  if (env && flagFor(ENV)) {
    report(findings, ENV, dep.lockFile, snippet, `${dep.name}@${dep.version} passes the process.env object to fetch, http.request, or https.request in ${spec}.`);
  }
  if (dynamic && flagFor(DYNAMIC)) {
    report(findings, DYNAMIC, dep.lockFile, snippet, `${dep.name}@${dep.version} has a top-level require or import whose argument is not a string literal in ${spec}.`);
  }
}

function installJsName(file: string): 'install' | 'preinstall' | 'postinstall' | undefined {
  if (file === 'package/install.js') {return 'install';}
  if (file === 'package/preinstall.js') {return 'preinstall';}
  if (file === 'package/postinstall.js') {return 'postinstall';}
  return undefined;
}

async function inspectPackage(
  dep: DirectDep,
  input: NpmDepthInput,
  findings: Finding[],
): Promise<void> {
  const versionDoc = await readVersion(input.cacheDir, dep.name, dep.version);
  const packIntegrity = textField(asRecord(versionDoc?.dist), 'integrity');
  const packTarball = textField(asRecord(versionDoc?.dist), 'tarball');
  if (urlBlocks(dep.resolved) || urlBlocks(packTarball)) {return;}
  const registryUrl = isRegistryUrl(dep.resolved) || isRegistryUrl(packTarball);
  if (dep.integrity === undefined && registryUrl && flagFor(SKIP)) {
    report(
      findings,
      SKIP,
      dep.lockFile,
      `${dep.name}@${dep.version} no integrity`,
      `${dep.name}@${dep.version} is a direct production dependency with a registry tarball URL and no integrity, so its tarball is refused.`,
    );
    return;
  }
  const expected = dep.integrity ?? packIntegrity;
  if (expected === undefined) {return;}
  const described = await loadDescriptor(input.cacheDir, dep.name);
  const bytes = described?.bytes ?? await loadIntegrityFile(input.cacheDir, expected);
  if (bytes !== undefined && !integrityMatches(expected, bytes)) {
    if (flagFor(HASH)) {
      report(
        findings,
        HASH,
        dep.lockFile,
        `${dep.name}@${dep.version} integrity`,
        `${dep.name}@${dep.version} cached tarball bytes do not match dist.integrity. Extraction stopped for this package.`,
      );
    }
    return;
  }
  if (
    npmFlag('NPM_REG_INTEGRITY') &&
    dep.integrity !== undefined &&
    packIntegrity !== undefined &&
    dep.integrity !== packIntegrity
  ) {return;}
  let entries = described?.entries;
  if ((entries === undefined || Object.keys(entries).length === 0) && bytes !== undefined) {
    entries = parseUstar(bytes);
  }
  if (entries === undefined) {return;}
  const names = new Set(Object.keys(entries));
  for (const name of names) {
    if (!isEscape(name) || !flagFor(PATH)) {continue;}
    report(findings, PATH, dep.lockFile, `${dep.name}@${dep.version} ${name}`, `${dep.name}@${dep.version} tarball entry ${name} is absolute or contains .. and was not extracted.`);
  }
  const safe: Record<string, string> = {};
  for (const [name, text] of Object.entries(entries)) {
    if (!isEscape(name)) {safe[name] = text;}
  }
  let count = 0;
  let unpacked = 0;
  for (const text of Object.values(entries)) {
    count += 1;
    unpacked += Buffer.byteLength(text);
  }
  if ((count > COUNT_CAP || unpacked > SIZE_CAP) && flagFor(SIZE)) {
    report(
      findings,
      SIZE,
      dep.lockFile,
      `${dep.name}@${dep.version} ${count} entries ${unpacked} bytes`,
      `${dep.name}@${dep.version} unpacked size or entry count exceeds the cap of 20 MB or 2000 entries. The cap is a limit, not a vulnerability count. Entries past the cap were not extracted.`,
    );
  }
  const extracted: Record<string, string> = {};
  let used = 0;
  let usedBytes = 0;
  for (const [name, text] of Object.entries(safe)) {
    const next = Buffer.byteLength(text);
    if (used >= COUNT_CAP || usedBytes + next > SIZE_CAP) {break;}
    extracted[name] = text;
    used += 1;
    usedBytes += next;
  }
  for (const name of Object.keys(safe)) {
    if (flagFor(NATIVE) && name.endsWith('.node')) {
      report(findings, NATIVE, dep.lockFile, `${dep.name}@${dep.version} ${name}`, `${dep.name}@${dep.version} contains ${name}. A prebuilt binary could not be reviewed as source.`);
    }
    const norm = normalizeSeparators(name);
    if (flagFor(HOOK) && (norm.includes('.git/hooks/') || norm.includes('.github/workflows/'))) {
      report(findings, HOOK, dep.lockFile, `${dep.name}@${dep.version} ${name}`, `${dep.name}@${dep.version} archives ${name}.`);
    }
    if (flagFor(HIDDEN) && norm.split('/').some((segment) => hiddenSegment(segment))) {
      report(findings, HIDDEN, dep.lockFile, `${dep.name}@${dep.version} ${name}`, `${dep.name}@${dep.version} path ${name} uses a bidi override or a hidden non-latin segment.`);
    }
    const loose = installJsName(name);
    if (loose !== undefined && flagFor(INSTALLJS)) {
      const pkgText = extracted['package/package.json'];
      const pkg = pkgText === undefined ? undefined : asRecord(parseJson(pkgText));
      const scripts = pkg === undefined ? {} : scriptMap(pkg);
      if (scripts[loose] === undefined) {
        report(findings, INSTALLJS, dep.lockFile, `${dep.name}@${dep.version} ${name}`, `${dep.name}@${dep.version} contains ${name} and scripts has no ${loose} key.`);
      }
    }
  }
  const pkgText = extracted['package/package.json'];
  const pkg = pkgText === undefined ? undefined : asRecord(parseJson(pkgText));
  if (pkg === undefined) {return;}
  if (flagFor(ID)) {
    const gotName = typeof pkg.name === 'string' ? pkg.name : '';
    const gotVersion = typeof pkg.version === 'string' ? pkg.version : '';
    if (gotName !== dep.name || gotVersion !== dep.version) {
      report(findings, ID, dep.lockFile, `${dep.name}@${dep.version} package.json ${gotName}@${gotVersion}`, `${dep.name}@${dep.version} tarball package.json is ${gotName}@${gotVersion}.`);
    }
  }
  const scripts = scriptMap(pkg);
  const lifecycle = lifecycleScripts(scripts);
  const packumentFlag = versionDoc?.hasInstallScript !== undefined
    ? versionDoc.hasInstallScript
    : asRecord(versionDoc)?.hasInstallScript;
  if (flagFor(LIFECYCLE) && packumentFlag === false && lifecycle.length > 0) {
    const listed = lifecycle.map(([key]) => key).join(', ');
    report(findings, LIFECYCLE, dep.lockFile, `${dep.name}@${dep.version} ${listed}`, `${dep.name}@${dep.version} tarball scripts include ${listed} while packument hasInstallScript is false.`);
  }
  for (const [key, body] of lifecycle) {
    const snippet = `${dep.name}@${dep.version} ${key}`;
    if (flagFor(NET) && containsToken(body, NET_TOKENS)) {
      report(findings, NET, dep.lockFile, snippet, `${dep.name}@${dep.version} ${key} script contains a network token.`);
    }
    if (flagFor(SHELL) && containsToken(body, SHELL_TOKENS)) {
      report(findings, SHELL, dep.lockFile, snippet, `${dep.name}@${dep.version} ${key} script contains a shell or downloader token.`);
    }
    if (flagFor(CRED) && containsToken(body, CRED_TOKENS)) {
      report(findings, CRED, dep.lockFile, snippet, `${dep.name}@${dep.version} ${key} script reads a credential file or token.`);
    }
    if (flagFor(OBFUSC) && hasObfuscatedEval(body)) {
      report(findings, OBFUSC, dep.lockFile, snippet, `${dep.name}@${dep.version} ${key} script passes a base64 literal of 32 or more characters to eval, Function, or spawn.`);
    }
  }
  if (flagFor(BIN) || flagFor(PATH)) {
    for (const bin of binPaths(pkg.bin)) {
      if (isEscape(bin)) {
        if (flagFor(PATH)) {
          report(findings, PATH, dep.lockFile, `${dep.name}@${dep.version} bin ${bin}`, `${dep.name}@${dep.version} bin path ${bin} is absolute or contains .. and was not treated as a missing bin.`);
        }
        continue;
      }
      if (flagFor(BIN) && !hasFile(names, bin)) {
        report(findings, BIN, dep.lockFile, `${dep.name}@${dep.version} bin ${bin}`, `${dep.name}@${dep.version} bin path ${bin} is inside the package and is not a file in the tarball.`);
      }
    }
  }
  if (flagFor(LICENSE)) {
    const packed = typeof pkg.license === 'string' ? pkg.license : undefined;
    const published = typeof versionDoc?.license === 'string' ? versionDoc.license : undefined;
    if (packed !== undefined && published !== undefined && packed !== published) {
      report(findings, LICENSE, dep.lockFile, `${dep.name}@${dep.version} ${packed} ${published}`, `${dep.name}@${dep.version} tarball license ${packed} differs from packument license ${published}. This does not judge the license.`);
    }
  }
  if (flagFor(MANIFEST)) {
    const packedDeps = stringMap(pkg.dependencies);
    const publishedDeps = stringMap(versionDoc?.dependencies);
    if (packedDeps !== undefined && publishedDeps !== undefined && !sameDeps(packedDeps, publishedDeps)) {
      report(findings, MANIFEST, dep.lockFile, `${dep.name}@${dep.version} dependencies`, `${dep.name}@${dep.version} tarball dependencies differ from the packument dependencies.`);
    }
  }
  if (flagFor(TOPLEVEL) || flagFor(ENV) || flagFor(DYNAMIC)) {
    for (const spec of entrySpecs(pkg)) {
      const text = fileText(extracted, spec);
      if (text === undefined) {continue;}
      await scanEntryFile(findings, dep, spec, text);
    }
  }
}

export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!anyFlag()) {return [];}
  const lock = pickLock(input);
  if (lock === undefined) {return [];}
  const findings: Finding[] = [];
  for (const dep of directProd(lock.text, input.manifestRaw, lock.file)) {
    await inspectPackage(dep, input, findings);
  }
  return findings;
}
