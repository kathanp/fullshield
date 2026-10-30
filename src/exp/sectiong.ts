/**
 * Phase 571. Section G checks. Off unless FULLSHIELD_EXPERIMENTAL_SECTIONG=1.
 * Flag off does not read the project and does not add a finding.
 */
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, extname, isAbsolute, join, relative } from 'node:path';

import type { ScanResult } from '../core/engine.js';
import { makeFindingId, type Finding, type Severity } from '../core/finding.js';
import { withExtraFindings } from '../modules/sast/parity.js';

const SECTIONG_FLAG = 'FULLSHIELD_EXPERIMENTAL_SECTIONG';

const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', '.fullshield']);
const SOURCE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

interface Loaded {
  rel: string;
  name: string;
  text: string;
}

interface RuleHit {
  n: string;
  severity: Severity;
  title: string;
  message: string;
  line: number;
  snippet: string;
}

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

function on(): boolean {
  return process.env[SECTIONG_FLAG] === '1';
}

function gid(n: string): string {
  return ['SECT', 'G', n].join('-');
}

function has(text: string, needle: string): boolean {
  return text.includes(needle);
}

function lineOf(text: string, needle: string): number {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if ((lines[i] ?? '').includes(needle)) {return i + 1;}
  }
  return 1;
}

function hash8(text: string): string {
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) {
    h = Math.imul(h, 33) ^ text.charCodeAt(i);
  }
  return (h >>> 0).toString(16).padStart(8, '0').slice(0, 8);
}

function finding(file: string, hit: RuleHit): Finding {
  const ruleId = gid(hit.n);
  return {
    id: makeFindingId(ruleId, file, hit.snippet),
    ruleId,
    module: 'sast',
    title: hit.title,
    severity: hit.severity,
    confidence: 'low',
    file,
    line: hit.line,
    snippet: hit.snippet,
    message: hit.message,
    remediation: 'Review this experimental section G check. It is off unless the flag is set.',
    source: 'rule',
  };
}

function authOk(text: string): boolean {
  return has(text, 'req.user') || has(text, 'req.session') || has(text, 'authorization') || has(text, 'requireAuth');
}

function pushHit(hits: RuleHit[], text: string, ok: boolean, hit: Omit<RuleHit, 'line' | 'snippet'> & { needle: string }): void {
  if (!ok) {return;}
  const line = lineOf(text, hit.needle);
  const snippet = text.split(/\r?\n/)[line - 1] ?? hit.needle;
  hits.push({ n: hit.n, severity: hit.severity, title: hit.title, message: hit.message, line, snippet });
}

function serverAction(text: string): boolean {
  return has(text, 'use server') && has(text, 'searchParams') && has(text, 'res.send') && !has(text, 'encodeURIComponent');
}

function unguarded(text: string): boolean {
  return (has(text, '@Get') || has(text, '@Post')) && !has(text, '@UseGuards');
}

function publicWrite(text: string): boolean {
  return has(text, 'publicProcedure') && has(text, 'id') && (has(text, 'update') || has(text, 'delete')) && !has(text, 'protectedProcedure');
}

function unsafeQuery(text: string): boolean {
  return (has(text, '$queryRawUnsafe') || has(text, '$executeRawUnsafe')) && has(text, 'req.');
}

function frameworkHits(text: string, hits: RuleHit[]): void {
  pushHit(hits, text, serverAction(text), { n: '003', severity: 'low', title: 'Server action HTML', message: 'searchParams is sent as HTML from a server action.', needle: 'searchParams' });
  pushHit(hits, text, unguarded(text), { n: '004', severity: 'low', title: 'Handler without guard', message: 'A route decorator has no UseGuards in this file.', needle: '@Get' });
  pushHit(hits, text, publicWrite(text), { n: '005', severity: 'low', title: 'Public procedure write', message: 'publicProcedure reads an id and writes a row.', needle: 'publicProcedure' });
  pushHit(hits, text, unsafeQuery(text), { n: '006', severity: 'low', title: 'Unsafe raw query', message: 'A string is passed to an unsafe raw query with request data.', needle: '$queryRawUnsafe' });
}

function grpcSink(text: string): boolean {
  return has(text, 'grpc') && has(text, 'request.') && (has(text, 'query(') || has(text, 'exec(') || has(text, 'fetch('));
}

function jobSink(text: string): boolean {
  return (has(text, 'bull') || has(text, 'sqs')) && (has(text, 'job.data') || has(text, 'body')) && (has(text, 'exec(') || has(text, 'query('));
}

function bothLengths(text: string): boolean {
  return has(text, 'Content-Length') && has(text, 'Transfer-Encoding') && has(text, 'req.');
}

function openPost(text: string): boolean {
  return (has(text, 'app.post') || has(text, 'app.put')) && !authOk(text);
}

function sinkHits(text: string, hits: RuleHit[]): void {
  pushHit(hits, text, grpcSink(text), { n: '009', severity: 'low', title: 'gRPC request sink', message: 'A grpc method passes request data into query, exec, or fetch.', needle: 'grpc' });
  pushHit(hits, text, has(text, 'res.send(message)') || has(text, 'res.end(message)'), { n: '010', severity: 'low', title: 'Message sent', message: 'A message callback argument is sent on the response.', needle: 'res.send(message)' });
  pushHit(hits, text, jobSink(text), { n: '011', severity: 'low', title: 'Job payload sink', message: 'A job payload is passed to exec or query.', needle: 'job.data' });
  pushHit(hits, text, bothLengths(text), { n: '012', severity: 'low', title: 'Ambiguous length headers', message: 'Content-Length and Transfer-Encoding both come from request data.', needle: 'Transfer-Encoding' });
  pushHit(hits, text, openPost(text), { n: '015', severity: 'low', title: 'State change without auth', message: 'A post or put handler does not read a user, a session, or auth.', needle: 'app.post' });
}

function unsafeLoad(text: string): boolean {
  return has(text, 'unsafeLoad') || (has(text, 'yaml.load') && has(text, 'DEFAULT_FULL_SCHEMA'));
}

function yamlUnsafe(text: string): boolean {
  if (!has(text, 'req.')) {return false;}
  if (has(text, 'JSON_SCHEMA') && !unsafeLoad(text)) {return false;}
  return unsafeLoad(text);
}

function zipSlip(text: string): boolean {
  return (has(text, 'entry.path') || has(text, 'entry.fileName')) && has(text, '../') && has(text, 'extract');
}

function openRedirect(text: string): boolean {
  return (has(text, 'redirect_uri') || has(text, 'redirect =') || has(text, 'redirect:')) && has(text, 'req.query') && !has(text, '[');
}

function promptFromRequest(text: string): boolean {
  return (has(text, 'system:') || has(text, 'prompt:') || has(text, 'messages:')) && (has(text, 'req.body') || has(text, 'req.query'));
}

function toolText(text: string): boolean {
  return has(text, 'description') && (has(text, 'ignore previous') || has(text, 'child_process'));
}

function dataHits(text: string, hits: RuleHit[]): void {
  pushHit(hits, text, zipSlip(text), { n: '016', severity: 'medium', title: 'Archive entry escapes', message: 'An archive entry path contains ../ and is extracted.', needle: '../' });
  pushHit(hits, text, yamlUnsafe(text), { n: '017', severity: 'medium', title: 'Unsafe YAML load', message: 'Request data is loaded with an unsafe YAML schema.', needle: 'yaml.load' });
  pushHit(hits, text, openRedirect(text), { n: '018', severity: 'medium', title: 'Open redirect', message: 'A redirect target is taken from the query string with no allowlist.', needle: 'req.query' });
  pushHit(hits, text, promptFromRequest(text), { n: '019', severity: 'low', title: 'Prompt from request', message: 'Request data is copied into a prompt, system, or messages field.', needle: 'req.' });
  pushHit(hits, text, toolText(text), { n: '020', severity: 'medium', title: 'Tool description', message: 'A tool description tells the model to ignore instructions or run a shell.', needle: 'description' });
}

function metadataHost(text: string): boolean {
  return has(text, '169.254.169.254') || has(text, '2852039166') || has(text, '[::ffff:169.254.169.254]');
}

function cachedCookie(text: string): boolean {
  return has(text, 'Cache-Control') && has(text, 'public') && has(text, 'req.headers.cookie');
}

function resetToken(text: string): boolean {
  return has(text, 'reset') && has(text, 'token=') && has(text, 'req.');
}

function loginOpen(text: string): boolean {
  return (has(text, "app.post('/login'") || has(text, 'app.post("/login"')) && !has(text, 'rateLimit');
}

function responseHits(text: string, hits: RuleHit[]): void {
  pushHit(hits, text, metadataHost(text), { n: '044', severity: 'medium', title: 'Metadata address', message: 'A user-controlled URL uses a cloud metadata host.', needle: '169.254.169.254' });
  pushHit(hits, text, cachedCookie(text), { n: '046', severity: 'medium', title: 'Cached credential body', message: 'A public cache header is set and the cookie is copied into the body.', needle: 'req.headers.cookie' });
  pushHit(hits, text, resetToken(text), { n: '047', severity: 'medium', title: 'Reset token in a URL', message: 'A reset link includes a token from request data.', needle: 'token=' });
  pushHit(hits, text, has(text, 'no such user') && has(text, 'bad password'), { n: '048', severity: 'low', title: 'Account enumeration', message: 'The file uses different messages for a missing user and a bad password.', needle: 'no such user' });
  pushHit(hits, text, loginOpen(text), { n: '049', severity: 'low', title: 'Login without a limiter', message: 'The login route does not call rateLimit in this file.', needle: '/login' });
}

function sameFileHits(text: string): RuleHit[] {
  const hits: RuleHit[] = [];
  frameworkHits(text, hits);
  sinkHits(text, hits);
  dataHits(text, hits);
  responseHits(text, hits);
  return hits;
}

function yamlHits(name: string, text: string): RuleHit[] {
  const hits: RuleHit[] = [];
  if (has(text, 'pull_request_target') && has(text, 'actions/checkout') && has(text, 'github.event.pull_request')) {
    hits.push({ n: '021', severity: 'medium', title: 'pull_request_target checkout', message: 'pull_request_target checks out pull-request code.', line: lineOf(text, 'pull_request_target'), snippet: 'pull_request_target' });
  }
  if (has(text, 'id-token: write') && has(text, 'github.event.pull_request')) {
    hits.push({ n: '050', severity: 'medium', title: 'OIDC on an untrusted ref', message: 'id-token write is set on a workflow that checks out an untrusted ref.', line: lineOf(text, 'id-token: write'), snippet: 'id-token: write' });
  }
  if (name.endsWith('.yml') || name.endsWith('.yaml')) {
    if (has(text, 'privileged: true') || has(text, 'hostPath') || has(text, 'hostNetwork: true')) {
      hits.push({ n: '022', severity: 'low', title: 'Privileged workload', message: 'The manifest sets privileged, hostPath, or hostNetwork.', line: 1, snippet: name });
    }
  }
  return hits;
}

function dockerHit(text: string): RuleHit | undefined {
  if (has(text, 'USER node')) {return undefined;}
  if (!has(text, 'USER') || has(text, 'USER root')) {
    return { n: '022', severity: 'low', title: 'Container runs as root', message: 'The Dockerfile has no USER, or USER root.', line: 1, snippet: 'USER' };
  }
  return undefined;
}

function quotedImport(text: string): string[] {
  const found: string[] = [];
  const re = /import\(\s*["']([^"']+)["']\s*\)/g;
  let match = re.exec(text);
  while (match !== null) {
    const spec = match[1] ?? '';
    if (spec.length > 0 && !spec.startsWith('.')) {found.push(spec);}
    match = re.exec(text);
  }
  return found;
}

function relativeImports(text: string): string[] {
  const found: string[] = [];
  const re = /(?:require\(\s*["'](\.[^"']+)["']\s*\)|from\s+["'](\.[^"']+)["'])/g;
  let match = re.exec(text);
  while (match !== null) {
    const spec = match[1] ?? match[2] ?? '';
    if (spec.length > 0) {found.push(spec);}
    match = re.exec(text);
  }
  return found;
}

function bodyNames(text: string): string[] {
  const names: string[] = [];
  const re = /(\w+)\s*=\s*req\.body\.\w+/g;
  let match = re.exec(text);
  while (match !== null) {
    const name = match[1];
    if (name !== undefined) {names.push(name);}
    match = re.exec(text);
  }
  return names;
}

function resolveRel(from: string, spec: string, files: readonly Loaded[]): Loaded | undefined {
  const base = spec.replace(/^\.\//, '');
  const dir = dirname(from);
  const stem = dir === '.' ? base : `${dir}/${base}`;
  return files.find((file) => file.rel === stem || file.rel === `${stem}.js` || file.rel === `${stem}.ts`);
}

function crossFileHits(files: readonly Loaded[]): Finding[] {
  const out: Finding[] = [];
  for (const file of files) {
    if (!SOURCE_EXT.has(extname(file.name))) {continue;}
    const names = bodyNames(file.text);
    for (const spec of relativeImports(file.text)) {
      const other = resolveRel(file.rel, spec, files);
      if (other === undefined) {continue;}
      for (const name of names) {
        if (has(other.text, `res.send(${name})`) || has(other.text, `res.end(${name})`)) {
          out.push(finding(other.rel, { n: '001', severity: 'low', title: 'Cross-file stored response', message: 'Request data from an importer is sent by the imported file.', line: lineOf(other.text, `res.send(${name})`), snippet: name }));
        }
      }
      if (has(file.text, '.save(') && has(file.text, 'req.') && has(other.text, 'SELECT') && has(other.text, '+') && !has(other.text, '$1')) {
        out.push(finding(other.rel, { n: '013', severity: 'medium', title: 'Second-order SQL', message: 'Saved request data is concatenated into SQL in an imported file.', line: lineOf(other.text, 'SELECT'), snippet: 'SELECT' }));
      }
    }
    const literals = quotedImport(file.text);
    if (literals.length > 0) {
      out.push(finding(file.rel, { n: '030', severity: 'low', title: 'Literal dynamic import', message: `Literal import: ${literals.join(', ')}`, line: lineOf(file.text, 'import('), snippet: literals.join(', ') }));
    }
  }
  return out;
}

function sourceHits(files: readonly Loaded[]): Finding[] {
  const out: Finding[] = [];
  for (const file of files) {
    const ext = extname(file.name);
    if (SOURCE_EXT.has(ext)) {
      for (const hit of sameFileHits(file.text)) {out.push(finding(file.rel, hit));}
    }
    if (file.name.endsWith('.yml') || file.name.endsWith('.yaml')) {
      for (const hit of yamlHits(file.name, file.text)) {out.push(finding(file.rel, hit));}
    }
    if (file.name === 'Dockerfile') {
      const hit = dockerHit(file.text);
      if (hit !== undefined) {out.push(finding(file.rel, hit));}
    }
  }
  return out;
}

async function readNamed(cwd: string, name: string): Promise<string | undefined> {
  try {
    return await readFile(join(cwd, name), 'utf8');
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === 'ENOENT') {return undefined;}
    fail(`${SECTIONG_FLAG} cannot read ${name}`);
  }
}

function outsideProject(cwd: string, target: string): boolean {
  const abs = isAbsolute(target) ? target : join(cwd, target);
  const rel = relative(cwd, abs);
  const home = homedir();
  return rel.startsWith('..') || isAbsolute(rel) || abs === home || abs.startsWith(`${home}/`);
}

async function refusePaths(cwd: string): Promise<void> {
  const text = await readNamed(cwd, 'sectiong-paths.txt');
  if (text === undefined) {return;}
  const paths = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0);
  for (const target of paths) {
    if (outsideProject(cwd, target)) {fail(`${SECTIONG_FLAG} refuses a path outside the project`);}
  }
}

async function openApiHit(cwd: string, files: readonly Loaded[]): Promise<Finding[]> {
  const text = await readNamed(cwd, 'openapi.yaml') ?? await readNamed(cwd, 'openapi.json');
  if (text === undefined || !has(text, '/admin')) {return [];}
  const found = files.some((file) => SOURCE_EXT.has(extname(file.name)) && has(file.text, '/admin'));
  if (found) {return [];}
  return [finding('openapi.yaml', { n: '008', severity: 'low', title: 'OpenAPI path missing', message: 'The OpenAPI file lists /admin and no source file contains that path.', line: 1, snippet: '/admin' })];
}

async function scopeHits(cwd: string): Promise<Finding[]> {
  const scopes = await readNamed(cwd, 'fullshield.scopes');
  if (scopes === undefined) {return [];}
  const lock = await readNamed(cwd, 'package-lock.json');
  if (lock === undefined) {return [];}
  const hits: Finding[] = [];
  for (const line of scopes.split(/\r?\n/)) {
    const name = line.trim();
    if (name.length === 0) {continue;}
    if (has(lock, name) && has(lock, 'registry.npmjs.org')) {
      hits.push(finding('package-lock.json', { n: '040', severity: 'medium', title: 'Public registry for an internal scope', message: `${name} resolves from registry.npmjs.org.`, line: 1, snippet: name }));
    }
  }
  return hits;
}

async function sbomHits(cwd: string): Promise<Finding[]> {
  const raw = await readNamed(cwd, 'sbom.json');
  if (raw === undefined) {return [];}
  const doc = JSON.parse(raw) as { components?: { name?: string }[] };
  const names = new Set((doc.components ?? []).map((row) => row.name).filter((name): name is string => name !== undefined));
  let listed: string[] = [];
  try {
    listed = await readdir(join(cwd, 'node_modules'));
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code !== 'ENOENT') {fail(`${SECTIONG_FLAG} cannot read node_modules`);}
  }
  const hits: Finding[] = [];
  for (const name of names) {
    if (!listed.includes(name)) {
      hits.push(finding('sbom.json', { n: '023', severity: 'low', title: 'SBOM name missing on disk', message: `${name} is in the SBOM and not in node_modules.`, line: 1, snippet: name }));
    }
  }
  for (const name of listed) {
    if (name.startsWith('.') || names.has(name)) {continue;}
    hits.push(finding('node_modules', { n: '023', severity: 'low', title: 'Installed name missing from the SBOM', message: `${name} is in node_modules and not in the SBOM.`, line: 1, snippet: name }));
  }
  return hits;
}

async function workspaceHit(cwd: string): Promise<Finding[]> {
  const changed = await readNamed(cwd, 'sectiong-changed.txt');
  const raw = await readNamed(cwd, 'package.json');
  if (changed === undefined || raw === undefined) {return [];}
  const doc = JSON.parse(raw) as { workspaces?: string[] };
  const spaces = doc.workspaces ?? [];
  const matched = new Set<string>();
  for (const path of changed.split(/\r?\n/)) {
    const trimmed = path.trim();
    for (const space of spaces) {
      if (trimmed === space || trimmed.startsWith(`${space}/`)) {matched.add(space);}
    }
  }
  if (matched.size === 0) {return [];}
  const message = [...matched].sort().join(', ');
  return [finding('sectiong-changed.txt', { n: '024', severity: 'low', title: 'Changed workspaces', message, line: 1, snippet: message })];
}

async function rulesHit(cwd: string): Promise<Finding[]> {
  const text = await readNamed(cwd, 'sectiong.rules.txt');
  if (text === undefined) {return [];}
  const pattern = text.match(/^pattern:\s*(.+)$/m)?.[1]?.trim() ?? '';
  const fixture = text.match(/^fixture:\s*(.+)$/m)?.[1]?.trim() ?? '';
  if (pattern.length === 0 || fixture.includes(pattern)) {return [];}
  return [finding('sectiong.rules.txt', { n: '025', severity: 'low', title: 'Rule fixture missed', message: 'The fixture string does not contain the rule pattern.', line: 1, snippet: pattern })];
}

async function expressDigest(cwd: string): Promise<Finding[]> {
  const raw = await readNamed(cwd, 'sectiong-osv.json');
  const imports = await readNamed(cwd, 'sectiong-imports.txt');
  if (raw === undefined || imports === undefined || !has(imports, 'express')) {return [];}
  const rows = JSON.parse(raw) as { id?: string; package?: string }[];
  const hits: Finding[] = [];
  for (const row of rows) {
    if (row.package !== 'express' || row.id === undefined) {continue;}
    hits.push(finding('sectiong-osv.json', { n: '035', severity: 'low', title: 'Local express advisory', message: row.id, line: 1, snippet: row.id }));
  }
  return hits;
}

function queryInside(line: string): string {
  const open = line.indexOf('"');
  const close = line.lastIndexOf('"');
  if (open < 0 || close <= open) {return '';}
  return line.slice(open + 1, close);
}

async function fingerprintHits(cwd: string, files: readonly Loaded[]): Promise<Finding[]> {
  const raw = await readNamed(cwd, 'sectiong.fp');
  if (raw === undefined || raw.trim().length === 0) {return [];}
  const want = hash8(raw.trim());
  const hits: Finding[] = [];
  for (const file of files) {
    const lines = file.text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? '';
      if (!has(line, '.query(')) {continue;}
      if (hash8(queryInside(line)) !== want) {continue;}
      hits.push(finding(file.rel, { n: '033', severity: 'low', title: 'Fingerprint matches a query', message: 'The stored fingerprint matches this query line.', line: i + 1, snippet: line }));
    }
  }
  return hits;
}

async function confirmHit(cwd: string): Promise<Finding[]> {
  const raw = await readNamed(cwd, 'sectiong-confirm.json');
  if (raw === undefined) {return [];}
  const doc = JSON.parse(raw) as { host?: string; rows?: { status?: string }[] };
  if (doc.host !== '127.0.0.1') {fail(`${SECTIONG_FLAG} confirm host must be 127.0.0.1`);}
  const bad = (doc.rows ?? []).some((row) => row.status === 'unconfirmed');
  if (!bad) {return [];}
  return [finding('sectiong-confirm.json', { n: '034', severity: 'low', title: 'Unconfirmed', message: 'unconfirmed is not a pass', line: 1, snippet: 'unconfirmed' })];
}

async function exceptionHit(cwd: string): Promise<Finding[]> {
  const raw = await readNamed(cwd, 'sectiong-exception.json');
  if (raw === undefined) {return [];}
  const doc = JSON.parse(raw) as { owner?: string; reason?: string; expires?: string; ruleId?: string; severity?: string };
  if (doc.owner === undefined || doc.owner.length === 0) {fail(`${SECTIONG_FLAG} exception is missing owner`);}
  const line = `${doc.owner} ${doc.reason ?? ''} ${doc.expires ?? ''} ${doc.ruleId ?? ''} ${doc.severity ?? ''}`;
  return [finding('sectiong-exception.json', { n: '042', severity: 'low', title: 'Exception audit', message: line, line: 1, snippet: doc.owner })];
}

function mermaidHits(rows: readonly Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const row of rows) {
    const trace = row.trace;
    if (trace === undefined || trace.length < 2) {continue;}
    const first = trace[0];
    const last = trace[trace.length - 1];
    if (first === undefined || last === undefined) {continue;}
    if (first.line === undefined || last.line === undefined) {continue;}
    if (first.file.length === 0 || last.file.length === 0) {continue;}
    const message = `flowchart LR\n  a["${first.file}:${first.line}"] --> b["${last.file}:${last.line}"]`;
    out.push(finding(first.file, { n: '032', severity: 'low', title: 'Taint flowchart', message, line: first.line, snippet: message }));
  }
  return out;
}

async function formatHit(cwd: string, rows: readonly Finding[]): Promise<Finding[]> {
  const text = await readNamed(cwd, 'sectiong-format.txt');
  if (text === undefined) {return [];}
  const brief = rows.map((row) => ({ ruleId: row.ruleId, file: row.file, line: row.line, severity: row.severity }));
  const message = JSON.stringify({ gitlab: brief, bitbucket: brief });
  return [finding('sectiong-format.txt', { n: '027', severity: 'low', title: 'GitLab and Bitbucket', message, line: 1, snippet: 'gitlab' })];
}

async function writeDelta(cwd: string, rows: readonly Finding[]): Promise<void> {
  const raw = await readNamed(cwd, 'sectiong-baseline.json');
  if (raw === undefined) {return;}
  const baseline = JSON.parse(raw) as string[];
  const ruleIds = rows.map((row) => row.ruleId).filter((id) => !baseline.includes(id));
  await writeFile(join(cwd, 'sectiong-delta.sarif.json'), `${JSON.stringify({ ruleIds })}\n`);
}

async function applyFixes(cwd: string): Promise<void> {
  const raw = await readNamed(cwd, 'sectiong-fixes.json');
  if (raw === undefined) {return;}
  const fixes = JSON.parse(raw) as { safe?: boolean; file?: string; text?: string }[];
  if (fixes.some((fix) => fix.safe !== true)) {fail(`${SECTIONG_FLAG} refuses an unsafe fix`);}
  for (const fix of fixes) {
    if (fix.file === undefined || fix.text === undefined) {continue;}
    if (fix.file.includes('..') || isAbsolute(fix.file)) {fail(`${SECTIONG_FLAG} refuses a path outside the project`);}
    await mkdir(dirname(join(cwd, fix.file)), { recursive: true });
    await writeFile(join(cwd, fix.file), fix.text);
  }
}

async function snapshotFix(cwd: string): Promise<void> {
  const original = await readNamed(cwd, 'sectiong-fix/target.js');
  const next = await readNamed(cwd, 'sectiong-fix/next.js');
  const still = await readNamed(cwd, 'sectiong-fix/still.txt');
  if (original === undefined || next === undefined || still === undefined) {return;}
  await writeFile(join(cwd, 'sectiong-fix/target.js.bak'), original);
  await writeFile(join(cwd, 'sectiong-fix/target.js'), next);
  if (still.trim() === 'yes') {await writeFile(join(cwd, 'sectiong-fix/target.js'), original);}
}

const cache = new Map<string, string>();

function remember(key: string, rows: Finding[]): Finding[] {
  const text = JSON.stringify(rows);
  const prev = cache.get(key);
  if (prev === text) {return JSON.parse(prev) as Finding[];}
  cache.set(key, text);
  return rows;
}

async function walk(dir: string, cwd: string, out: Loaded[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {continue;}
    if (entry.isDirectory()) {
      if (SKIP.has(entry.name)) {continue;}
      await walk(join(dir, entry.name), cwd, out);
      continue;
    }
    const name = entry.name;
    const ext = extname(name);
    const keep = SOURCE_EXT.has(ext) || name === 'Dockerfile' || name.endsWith('.yml') || name.endsWith('.yaml') || name.endsWith('.json') || name.endsWith('.txt');
    if (!keep) {continue;}
    const abs = join(dir, name);
    const text = await readFile(abs, 'utf8');
    if (text.length > 200_000) {continue;}
    out.push({ rel: relative(cwd, abs), name, text });
  }
}

async function collect(cwd: string, existing: readonly Finding[]): Promise<Finding[]> {
  await refusePaths(cwd);
  const files: Loaded[] = [];
  await walk(cwd, cwd, files);
  const rows = [
    ...sourceHits(files),
    ...crossFileHits(files),
    ...await openApiHit(cwd, files),
    ...await scopeHits(cwd),
    ...await sbomHits(cwd),
    ...await workspaceHit(cwd),
    ...await rulesHit(cwd),
    ...await expressDigest(cwd),
    ...await fingerprintHits(cwd, files),
    ...await confirmHit(cwd),
    ...await exceptionHit(cwd),
    ...mermaidHits(existing),
    ...await formatHit(cwd, existing),
  ];
  await writeDelta(cwd, rows);
  await snapshotFix(cwd);
  await applyFixes(cwd);
  return remember(cwd, rows);
}

export async function withSectionG(result: ScanResult, cwd: string): Promise<ScanResult> {
  if (!on()) {return result;}
  return withExtraFindings(result, await collect(cwd, result.findings));
}
