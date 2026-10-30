/**
 * Phase 573. Section H auth, CI text, and output checks.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECTIONG=1.
 * Flag off does not read the project and does not add a finding.
 */
import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { extname, isAbsolute, join, relative } from 'node:path';

import type { ScanResult } from '../core/engine.js';
import { makeFindingId, type Finding, type Severity } from '../core/finding.js';
import { withExtraFindings } from '../modules/sast/parity.js';

const SECTIONG_FLAG = 'FULLSHIELD_EXPERIMENTAL_SECTIONG';
const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', '.fullshield']);
const SOURCE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const LOCK_SKIP = new Set(['.js', '.jsx', '.ts', '.tsx']);
const HASHES = ["createHash('md5'", "createHash('sha1'", 'createHash("md5"', 'createHash("sha1"'];
const FIELDS = ['script', 'license', 'native'] as const;
const DAY_MS = 86_400_000;

interface Loaded {
  rel: string;
  name: string;
  text: string;
}

interface Hit {
  n: string;
  severity: Severity;
  title: string;
  message: string;
  needle: string;
}

interface Bump {
  name?: string;
  from?: string;
  to?: string;
  override?: boolean;
}

interface Delta {
  from: Record<string, string>;
  to: Record<string, string>;
}

interface Markers {
  format: boolean;
  doctor: number | undefined;
  cacheMs: number | undefined;
  relative: boolean;
  mask: string[];
  report: boolean;
  lockOnly: boolean;
  policy: { ruleIds: string[] } | undefined;
  epss: Record<string, number> | undefined;
  bumps: Bump[] | undefined;
  delta: Delta | undefined;
  offline: boolean;
}

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

function on(): boolean {
  return process.env[SECTIONG_FLAG] === '1';
}

function hid(n: string): string {
  return ['SECT', 'H', n].join('-');
}

function lineOf(text: string, needle: string): number {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if ((lines[i] ?? '').includes(needle)) {return i + 1;}
  }
  return 1;
}

function row(file: string, text: string, hit: Hit): Finding {
  const line = lineOf(text, hit.needle);
  const snippet = text.split(/\r?\n/)[line - 1] ?? hit.needle;
  const ruleId = hid(hit.n);
  return {
    id: makeFindingId(ruleId, file, snippet),
    ruleId,
    module: 'sast',
    title: hit.title,
    severity: hit.severity,
    confidence: 'low',
    file,
    line,
    snippet,
    message: hit.message,
    remediation: 'Review this experimental section H check. It is off unless the section G flag is set.',
    source: 'rule',
  };
}

function add(hits: Finding[], file: Loaded, ok: boolean, hit: Omit<Hit, 'needle'>): void {
  if (!ok) {return;}
  hits.push(row(file.rel, file.text, { ...hit, needle: file.text.slice(0, 20) || hit.title }));
}

function note(file: string, n: string, title: string, message: string): Finding {
  return row(file, message, { n, severity: 'low', title, message, needle: message.slice(0, 40) || title });
}

async function text(cwd: string, name: string): Promise<string | undefined> {
  try {
    return await readFile(join(cwd, name), 'utf8');
  } catch {
    return undefined;
  }
}

function jsonOf(body: string | undefined): unknown {
  if (body === undefined) {return undefined;}
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
}

function daysOf(body: string | undefined): number | undefined {
  if (body === undefined || !/^\d+$/.test(body.trim())) {return undefined;}
  return Number(body.trim());
}

function entries(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function policyOf(value: unknown): { ruleIds: string[] } | undefined {
  const row = entries(value);
  if (row === undefined || !Array.isArray(row.ruleIds)) {return undefined;}
  return { ruleIds: row.ruleIds.filter((id): id is string => typeof id === 'string') };
}

function epssOf(value: unknown): Record<string, number> | undefined {
  const row = entries(value);
  if (row === undefined) {return undefined;}
  const out: Record<string, number> = {};
  for (const [key, score] of Object.entries(row)) {
    if (typeof score === 'number') {out[key] = score;}
  }
  return out;
}

function bumpsOf(value: unknown): Bump[] | undefined {
  if (!Array.isArray(value)) {return undefined;}
  const rows: Bump[] = [];
  for (const item of value) {
    const row = entries(item);
    if (row === undefined) {continue;}
    rows.push({
      name: typeof row.name === 'string' ? row.name : undefined,
      from: typeof row.from === 'string' ? row.from : undefined,
      to: typeof row.to === 'string' ? row.to : undefined,
      override: row.override === true,
    });
  }
  return rows;
}

function recordOf(value: unknown): Record<string, string> {
  const row = entries(value);
  const out: Record<string, string> = {};
  if (row === undefined) {return out;}
  for (const [key, item] of Object.entries(row)) {
    if (typeof item === 'string') {out[key] = item;}
  }
  return out;
}

function deltaOf(value: unknown): Delta | undefined {
  const row = entries(value);
  if (row === undefined) {return undefined;}
  return { from: recordOf(row.from), to: recordOf(row.to) };
}

async function cacheMs(cwd: string): Promise<number | undefined> {
  try {
    return (await stat(join(cwd, 'sectionh-osv-cache.json'))).mtimeMs;
  } catch {
    return undefined;
  }
}

async function readMarkers(cwd: string): Promise<Markers> {
  const mask = await text(cwd, 'sectionh-mask.txt');
  return {
    format: (await text(cwd, 'sectionh-format.txt')) !== undefined,
    doctor: daysOf(await text(cwd, 'sectionh-doctor.txt')),
    cacheMs: await cacheMs(cwd),
    relative: (await text(cwd, 'sectionh-relative.txt')) !== undefined,
    mask: (mask ?? '').split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0),
    report: (await text(cwd, 'sectionh-report.txt')) !== undefined,
    lockOnly: (await text(cwd, 'sectionh-lockonly.txt')) !== undefined,
    policy: policyOf(jsonOf(await text(cwd, 'sectionh-policy.json'))),
    epss: epssOf(jsonOf(await text(cwd, 'sectionh-epss.json'))),
    bumps: bumpsOf(jsonOf(await text(cwd, 'sectionh-bumps.json'))),
    delta: deltaOf(jsonOf(await text(cwd, 'sectionh-delta.json'))),
    offline: (await text(cwd, 'sectionh-offline.txt')) !== undefined,
  };
}

function keep(name: string, lockOnly: boolean): boolean {
  const ext = extname(name);
  if (lockOnly && LOCK_SKIP.has(ext)) {return false;}
  if (SOURCE_EXT.has(ext)) {return true;}
  if (name === 'Dockerfile' || name.endsWith('Dockerfile')) {return true;}
  if (name.includes('compose')) {return true;}
  if (ext === '.yml' || ext === '.yaml') {return true;}
  return name === '.gitignore' || name === '.dockerignore';
}

async function load(dir: string, cwd: string, out: Loaded[], lockOnly: boolean): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {continue;}
    if (entry.isDirectory()) {
      if (!SKIP.has(entry.name)) {await load(join(dir, entry.name), cwd, out, lockOnly);}
      continue;
    }
    if (!keep(entry.name, lockOnly)) {continue;}
    const abs = join(dir, entry.name);
    const rel = relative(cwd, abs).split('\\').join('/');
    const body = await readFile(abs, 'utf8');
    if (body.length <= 200_000) {out.push({ rel, name: entry.name, text: body });}
  }
}

function oauth(text: string): boolean {
  const redirect = (text.includes('oauth') || text.includes('authorize')) && text.includes('redirect') && !text.includes('state');
  const token = text.includes('token') && text.includes('code') && !text.includes('verifier');
  return redirect || token;
}

function openRedirect(text: string): boolean {
  const query = text.includes('req.query.next') || text.includes('req.query.return');
  return text.includes('res.redirect') && query && !text.includes('[');
}

function secretLine(line: string): boolean {
  if (line.includes('process.env')) {return false;}
  if (/secret:\s*['"]/.test(line)) {return true;}
  return /jwt\.sign\(/.test(line) && /['"][^'"]+['"]/.test(line);
}

function cookieLine(line: string): boolean {
  const none = line.includes('SameSite=None') || line.includes("sameSite: 'none'");
  return none && !line.toLowerCase().includes('secure');
}

function cookie(rel: string, text: string): boolean {
  if (rel.includes('test')) {return false;}
  return text.split(/\r?\n/).some((line) => cookieLine(line));
}

function weakHash(text: string): boolean {
  return text.includes('password') && HASHES.some((needle) => text.includes(needle));
}

function accountUpdate(text: string): boolean {
  const named = text.includes('email') || text.includes('password');
  return named && text.includes('.update(') && !text.includes('currentPassword') && !text.includes('req.session');
}

function presign(text: string): boolean {
  const call = text.includes('getSignedUrl') || text.includes('presign');
  return call && !text.includes('expiresIn') && !text.includes('Expires');
}

function publicRead(text: string): boolean {
  return text.includes('public-read-write') || text.includes('public-read');
}

function sourceHits(file: Loaded, hits: Finding[]): void {
  if (!SOURCE_EXT.has(extname(file.name))) {return;}
  const body = file.text;
  add(hits, file, oauth(body), { n: '028', severity: 'medium', title: 'OAuth redirect or token request', message: 'A redirect or token request is missing state or a verifier.' });
  add(hits, file, openRedirect(body), { n: '029', severity: 'medium', title: 'Open redirect', message: 'res.redirect receives a query path and the file has no array literal.' });
  add(hits, file, body.split(/\r?\n/).some((line) => secretLine(line)), { n: '030', severity: 'medium', title: 'Literal secret', message: 'A secret or jwt.sign call uses a string literal.' });
  add(hits, file, cookie(file.rel, body), { n: '031', severity: 'medium', title: 'Cookie without secure', message: 'A SameSite none cookie does not set secure.' });
  add(hits, file, weakHash(body), { n: '032', severity: 'medium', title: 'Weak password hash', message: 'A password is hashed with md5 or sha1.' });
  add(hits, file, accountUpdate(body), { n: '033', severity: 'low', title: 'Account update', message: 'An account update does not read the current password or the session.' });
  add(hits, file, presign(body), { n: '034', severity: 'low', title: 'Presign without expiry', message: 'A signed URL does not set an expiry.' });
  add(hits, file, publicRead(body), { n: '035', severity: 'medium', title: 'Public object ACL', message: 'Application source names a public-read ACL.' });
}

function yml(name: string): boolean {
  const ext = extname(name);
  return ext === '.yml' || ext === '.yaml';
}

function unpinnedLine(line: string): boolean {
  const at = line.indexOf('uses:');
  if (at < 0) {return false;}
  const value = line.slice(at + 'uses:'.length).trim();
  if (value.includes('actions/checkout') || value.includes('actions/setup-node')) {return false;}
  if (!value.includes('/')) {return false;}
  return !/[0-9a-f]{40}$/i.test(value);
}

function blocks(text: string): string[] {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === 'jobs:');
  if (start < 0) {return [text];}
  const out: string[] = [];
  let current: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith('  ') && !line.startsWith('   ') && line.trim().endsWith(':')) {
      if (current.length > 0) {out.push(current.join('\n'));}
      current = [line];
    } else if (current.length > 0) {current.push(line);}
  }
  if (current.length > 0) {out.push(current.join('\n'));}
  return out.length > 0 ? out : [text];
}

function otherUse(line: string): boolean {
  if (!line.includes('uses:')) {return false;}
  const value = line.split('uses:')[1] ?? '';
  if (value.includes('actions/checkout') || value.includes('actions/setup-node')) {return false;}
  return value.includes('/');
}

function workflowHits(file: Loaded, hits: Finding[]): void {
  if (!yml(file.name)) {return;}
  const body = file.text;
  const injected = body.split(/\r?\n/).some((line) => line.includes('run:') && line.includes('${{ github.event.'));
  add(hits, file, injected, { n: '036', severity: 'medium', title: 'Event interpolation', message: 'A run line interpolates a GitHub event value.' });
  add(hits, file, body.split(/\r?\n/).some((line) => unpinnedLine(line)), { n: '037', severity: 'low', title: 'Unpinned action', message: 'A uses value is not pinned to 40 hex characters.' });
  const secret = blocks(body).some((block) => block.split(/\r?\n/).some((line) => otherUse(line)) && block.includes('secrets.'));
  add(hits, file, secret, { n: '038', severity: 'medium', title: 'Third-party action secret', message: 'A job passes a secret to an action outside the allow list.' });
  add(hits, file, body.includes('persist-credentials: true') && body.includes('pull_request'), { n: '039', severity: 'medium', title: 'Persisted credentials', message: 'pull_request keeps checkout credentials.' });
  const write = body.includes('contents: write') || body.includes('id-token: write');
  add(hits, file, body.includes('pull_request:') && write, { n: '040', severity: 'medium', title: 'Pull request write token', message: 'pull_request can write contents or request an id token.' });
  add(hits, file, body.includes('npm publish') && body.includes('NODE_AUTH_TOKEN') && !body.includes('id-token:'), { n: '044', severity: 'medium', title: 'Publish token', message: 'npm publish uses NODE_AUTH_TOKEN without an id token.' });
}

function dockerLine(line: string): boolean {
  const start = line.startsWith('ARG') || line.startsWith('ENV') || line.startsWith('COPY');
  if (!start) {return false;}
  return line.includes('.env') || line.includes('id_rsa') || line.includes('.npmrc');
}

function composeLine(line: string): boolean {
  if (!line.includes('PASSWORD') || line.includes('${')) {return false;}
  return line.includes('"') || line.includes("'");
}

function packHits(file: Loaded, hits: Finding[]): void {
  const body = file.text;
  if (file.name === '.gitignore' || file.name === '.dockerignore') {
    add(hits, file, !body.includes('.env'), { n: '041', severity: 'low', title: 'Ignore file misses .env', message: 'An ignore file exists and does not list .env.' });
  }
  if (file.name === 'Dockerfile' || file.name.endsWith('Dockerfile')) {
    const secret = body.split(/\r?\n/).some((line) => dockerLine(line.trim()));
    add(hits, file, secret, { n: '042', severity: 'medium', title: 'Dockerfile secret', message: 'A Dockerfile copies or sets a secret file.' });
  }
  if (file.name.includes('compose') && body.includes('ports:')) {
    const quoted = body.split(/\r?\n/).some((line) => composeLine(line));
    add(hits, file, quoted, { n: '043', severity: 'medium', title: 'Compose password literal', message: 'A compose file sets PASSWORD to a quoted literal.' });
  }
}

function fileHits(file: Loaded, hits: Finding[]): void {
  sourceHits(file, hits);
  workflowHits(file, hits);
  packHits(file, hits);
}

function reviewdog(findings: Finding[]): string {
  const rows = findings.map((item) => ({
    ruleId: item.ruleId,
    file: item.file ?? '',
    line: item.line ?? 1,
    severity: item.severity,
  }));
  return JSON.stringify({ reviewdog: rows });
}

function relOf(file: string, cwd: string): string {
  if (isAbsolute(file)) {return relative(cwd, file).split('\\').join('/');}
  return file.split('\\').join('/');
}

function cacheHit(markers: Markers, hits: Finding[]): void {
  if (markers.doctor === undefined) {return;}
  if (markers.cacheMs === undefined) {
    hits.push(note('sectionh-doctor.txt', '047', 'Cache missing', 'cache is missing'));
    return;
  }
  const days = Math.floor((Date.now() - markers.cacheMs) / DAY_MS);
  if (days > markers.doctor) {hits.push(note('sectionh-doctor.txt', '047', 'Cache age', `cache is ${days} days old`));}
}

function policyMessage(findings: Finding[], ruleIds: string[]): string {
  const ids = new Set(ruleIds);
  return findings.map((item) => item.ruleId).filter((id) => ids.has(id)).join(' ');
}

function epssMessage(findings: Finding[], epss: Record<string, number>): string {
  const lines: string[] = [];
  for (const item of findings) {
    const score = epss[item.ruleId];
    if (typeof score !== 'number') {continue;}
    lines.push(`${item.ruleId} ${score} ${item.severity} unspecified`);
  }
  return lines.join('\n');
}

function patchOnly(from: string, to: string): boolean {
  const left = from.split('.');
  const right = to.split('.');
  if (left.length !== 3 || right.length !== 3) {return false;}
  return left[0] === right[0] && left[1] === right[1] && left[2] !== right[2];
}

function pickBump(rows: Bump[]): string | undefined {
  const over = rows.find((item) => item.override === true && typeof item.name === 'string');
  if (over?.name) {return `${over.name} override`;}
  const patch = rows.find((item) => typeof item.name === 'string' && patchOnly(item.from ?? '', item.to ?? ''));
  if (patch?.name) {return `${patch.name} patch`;}
  return undefined;
}

function changedField(delta: Delta): string | undefined {
  return FIELDS.find((field) => {
    const left = delta.from[field];
    const right = delta.to[field];
    return left !== right && (left !== undefined || right !== undefined);
  });
}

function outputHits(markers: Markers, findings: Finding[], cwd: string, hits: Finding[]): void {
  if (markers.format) {hits.push(note('sectionh-format.txt', '045', 'Reviewdog JSON', reviewdog(findings)));}
  cacheHit(markers, hits);
  if (markers.relative) {
    hits.push(note('sectionh-relative.txt', '048', 'Relative paths', findings.map((item) => relOf(item.file ?? '', cwd)).join('\n')));
  }
  if (markers.policy) {hits.push(note('sectionh-policy.json', '053', 'Policy rule ids', policyMessage(findings, markers.policy.ruleIds)));}
  const epss = markers.epss === undefined ? '' : epssMessage(findings, markers.epss);
  if (epss.length > 0) {hits.push(note('sectionh-epss.json', '054', 'Local EPSS', epss));}
  const bump = markers.bumps === undefined ? undefined : pickBump(markers.bumps);
  if (bump !== undefined) {hits.push(note('sectionh-bumps.json', '055', 'Bump choice', bump));}
  const field = markers.delta === undefined ? undefined : changedField(markers.delta);
  if (field !== undefined) {hits.push(note('sectionh-delta.json', '056', 'Delta field', field));}
}

function maskOne(item: Finding, lines: string[]): Finding {
  let message = item.message;
  for (const line of lines) {
    if (line.length > 0 && message.includes(line)) {message = message.split(line).join('[masked]');}
  }
  return message === item.message ? item : { ...item, message };
}

function maskFindings(findings: Finding[], lines: string[]): Finding[] {
  if (lines.length === 0) {return findings;}
  return findings.map((item) => maskOne(item, lines));
}

async function mapName(cwd: string, dir: string): Promise<string | undefined> {
  try {
    const names = await readdir(join(cwd, dir));
    return names.find((name) => name.endsWith('.map'));
  } catch {
    return undefined;
  }
}

async function mapOne(item: Finding, cwd: string): Promise<Finding> {
  const file = (item.file ?? '').split('\\').join('/');
  const parts = file.split('/');
  if (!parts.includes('dist')) {return item;}
  const map = await mapName(cwd, parts.slice(0, -1).join('/'));
  if (map === undefined) {return item;}
  return { ...item, message: `${item.message} ${map}` };
}

async function mapFindings(findings: Finding[], cwd: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const item of findings) {out.push(await mapOne(item, cwd));}
  return out;
}

async function writeReport(cwd: string, markers: Markers, findings: Finding[]): Promise<void> {
  if (!markers.report) {return;}
  const body = JSON.stringify({ ruleIds: findings.map((item) => item.ruleId) });
  await writeFile(join(cwd, 'sectionh-report.json'), body, { mode: 0o600 });
}

function same(left: Finding[], right: Finding[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function finish(result: ScanResult, mapped: Finding[], hits: Finding[]): ScanResult {
  const base = same(result.findings, mapped) ? result : { ...result, findings: mapped };
  return hits.length === 0 ? base : withExtraFindings(base, hits);
}

export async function withSectionH2(result: ScanResult, cwd: string): Promise<ScanResult> {
  if (!on()) {return result;}
  const markers = await readMarkers(cwd);
  if (markers.offline && markers.cacheMs === undefined) {
    fail(`${SECTIONG_FLAG} refuses to scan without the local cache`);
  }
  const files: Loaded[] = [];
  await load(cwd, cwd, files, markers.lockOnly);
  const hits: Finding[] = [];
  for (const file of files) {fileHits(file, hits);}
  outputHits(markers, result.findings, cwd, hits);
  const mapped = await mapFindings(maskFindings(result.findings, markers.mask), cwd);
  await writeReport(cwd, markers, result.findings);
  return finish(result, mapped, hits);
}
