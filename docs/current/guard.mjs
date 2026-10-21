#!/usr/bin/env node
// scripts/autopilot/guard.mjs — mechanical enforcement for AUTOPILOT.md (FullShield). No dependencies.
// Dev only: not in the `files` allowlist, never packed.
//
// Run start
//   --init --run <name> --version <x.y.z>   SPEC has the R26 amendment, .gitignore entries, clean tree,
//                                           install hook, snapshot protected files, create run/<name>
//                                           from the base branch (next), write RUN_STATE skeleton
// Phase 1 (spec)
//   --approve-spec --run <name>             PERSON ONLY, in a terminal: freeze the SPEC for this run
//   --verify-spec [--card <id>]             approval present and SPEC unchanged; no [PROPOSED] marks;
//                                           card shape, flag, numbers all in that card's SPEC rows
// Phases 3-5 (tests, code, review)
//   --card <id> --role test|code [--base <ref>]   ownership, R3 (no edits to existing tests), banned
//                                                 test patterns, fixture secret literals, stubs, flags
//   --mutate --card <id>                          every mutant must fail done_when (runs in a temp
//                                                 worktree; never writes the working tree, see D14)
// Phases 7-9 (gate, docs, squash)
//   --verify-protected                      no "never" file changed, deleted, or added since --init
//   --verify-history [--base <ref>]         run/<name>: one clean commit per phase, no noise
//   --verify-docs [--base <ref>]            doc-version-check, CHANGELOG top entry, version mentions,
//                                           new rule IDs / FS-E codes / flags documented
//   --verify-no-logs                        .autopilot/ holds only guard state; no proposals, no .log,
//                                           no new reports/ or docs/history/ files in the run
//   --squash --run <name> --version <v>     release/<v> = base + exactly one commit, same tree as run/<name>
//   --verify-release --version <v>          that one commit, package version, lockfile, changelog, tag
// Phase 10 (release, read-only)
//   --release-check --version <v>           list blockers and the person's push/PR/tag/approve order
// Phase 11
//   --cleanup --run <name> --version <v>    after release/<v> is in origin/main: erase the run
// Hook
//   --install-hooks | --commit-msg <file>
//
// This script never pushes, publishes, tags, logs in, or calls the network.

import { execFileSync, execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : d;
};

// .autopilot/ is gitignored, so it exists only in the main checkout. Worker worktrees resolve it
// there through git's common dir.
const MAIN_ROOT = (() => {
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return resolve(common, '..');
  } catch {
    return process.cwd();
  }
})();
const STATE = '.autopilot/';
const STATE_DIR = join(MAIN_ROOT, STATE);
const PROTECTED = join(STATE_DIR, 'protected.json');
const HASHES = join(STATE_DIR, 'protected.sha256');
const APPROVAL = join(STATE_DIR, 'spec-approved.json');
const RUN_STATE = join(STATE_DIR, 'RUN_STATE.md');
const CARDS = join(STATE_DIR, 'cards');
const PKG = 'package.json';
const CHANGELOG = 'CHANGELOG.md';
const REQUIRED_IGNORES = ['.autopilot/', 'AUTOPILOT.md'];
// The only things .autopilot/ may hold (AUTOPILOT.md 1a).
const STATE_ALLOWED = new Set(['protected.json', 'protected.sha256', 'spec-approved.json', 'RUN_STATE.md', 'cards']);
const FLAG_RE = /FULLSHIELD_EXPERIMENTAL_[A-Z0-9_]+/g;
const RULE_ID_RE = /\bid:\s*['"]([A-Z]+(?:-[A-Z0-9]+)*-\d{3})['"]/g;
const ERR_CODE_RE = /\bFS-E\d{3}\b/g;
const CARD_ID_RE = /^phase-\d+[a-z]?$/;
const errors = [];
const warnings = [];

const git = (...a) => execFileSync('git', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const gitOk = (...a) => {
  try {
    git(...a);
    return true;
  } catch {
    return false;
  }
};
const lines = (s) => s.split('\n').filter(Boolean);
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const die = (msg) => {
  console.error(`guard: ${msg}`);
  process.exit(2);
};
const loadJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : die(`missing ${p}`));
const readJsonAt = (ref, p) => JSON.parse(git('show', `${ref}:${p}`));
const need = (n) => opt(n) ?? die(`${n} <value> is required`);
const SEMVER = /^\d+\.\d+\.\d+$/;
const needVersion = () => {
  const v = need('--version');
  if (!SEMVER.test(v)) die(`--version must be x.y.z, got "${v}"`);
  return v;
};
const cmpVer = (a, b) => {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
};
const branchExists = (b) => gitOk('rev-parse', '--verify', '--quiet', `refs/heads/${b}`);
const currentBranch = () => {
  try {
    return git('symbolic-ref', '--short', 'HEAD');
  } catch {
    return '';
  }
};
const cleanTree = () => !git('status', '--porcelain', '--untracked-files=no');
const fileAt = (ref, p) => {
  try {
    return git('show', `${ref}:${p}`);
  } catch {
    return null;
  }
};

// Glob: "**/" matches zero or more directories, "**" anything, "*" one path segment.
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const segRe = (p) => p.split('*').map(esc).join('[^/]*');
const globRe = (g) =>
  new RegExp(
    '^' +
      g
        .split('**/')
        .map((part) => part.split('**').map(segRe).join('.*'))
        .join('(?:.*/)?') +
      '$',
  );
const matches = (f, p) => globRe(p).test(f);
const inAny = (f, ps) => ps.some((p) => matches(f, p));
const isTestFile = (f) => /^test\//.test(f) || /\.test\.[cm]?[jt]s$/.test(f);
const isFixture = (f) => /^test\/fixtures\//.test(f);

const DEFAULT_CONFIG = {
  base: 'next',
  spec: 'SECURITY_SCANNER_SPEC.md',
  decisions: 'docs/DECISIONS.md',
  amendmentMarker: 'R26. AUTOPILOT runs',
  worktreeRoot: '../fullshield-wt',
  never: [],
  masterOnly: [],
  docs: { files: [], mustMentionVersion: [], errorsDoc: 'docs/errors.md', flagDoc: 'README.md' },
  noAddDuringRun: ['reports/**', 'docs/history/**', 'docs/proposals/**'],
  releaseManual: [],
};
const config = () => {
  const raw = existsSync(PROTECTED) ? JSON.parse(readFileSync(PROTECTED, 'utf8')) : {};
  return { ...DEFAULT_CONFIG, ...raw, docs: { ...DEFAULT_CONFIG.docs, ...(raw.docs ?? {}) } };
};
const CFG = config();
const SPEC = CFG.spec;
const BASE = opt('--base', CFG.base);

const loadCard = (id) => {
  if (!CARD_ID_RE.test(id)) die(`card id must be phase-<N> (R19), got "${id}"`);
  const card = loadJson(join(CARDS, `${id}.json`));
  if (card.id !== id) die(`card file ${id}.json has id "${card.id}"`);
  return card;
};

// Files tracked at HEAD (or in the work tree) that match a list of globs.
const expand = (globs) => lines(git('-C', MAIN_ROOT, 'ls-files')).filter((f) => inAny(f, globs));

// ---------------------------------------------------------------- commit-message policy
// run/*: one "phase-N:" commit per phase, plus one each of "spec:", "docs:", "chore:".
// release/<v>: exactly "release: <v>". Other branches (next, main, wk/*, phase-*) are not policed
// here: the SPEC's own conventions ("snapshot:", "report:") still apply on next.
const TASK_RE = /^(phase-\d+[a-z]?|spec|docs|chore): \S/;
const NOISE_RE = /^(report|snapshot|wip|verify|checkpoint|fixup!|squash!|amend!|Revert ")/i;
function msgProblem(subject, branch = '') {
  if (branch.startsWith('release/')) {
    const want = `release: ${branch.slice('release/'.length)}`;
    return subject === want ? null : `release branch takes one commit "${want}", got "${subject}"`;
  }
  if (NOISE_RE.test(subject)) return `bookkeeping/noise commit: "${subject}" (squash it into its phase)`;
  if (!TASK_RE.test(subject)) return `non-conforming subject: "${subject}" (want "phase-N: <summary>", R19)`;
  return null;
}
const taskId = (subject) => subject.match(TASK_RE)?.[1];
const stripTrailers = (msg) => msg.replace(/^Co-authored-by:.*\b(cursor|agent|bot|claude)\b.*\n?/gim, '');

// ---------------------------------------------------------------- shared steps
function installHooks() {
  const dir = git('rev-parse', '--git-path', 'hooks');
  mkdirSync(dir, { recursive: true });
  const hook = join(dir, 'commit-msg');
  if (existsSync(hook) && !readFileSync(hook, 'utf8').includes('scripts/autopilot/guard.mjs'))
    die(`${hook} already exists and is not the guard's hook; merge them by hand`);
  writeFileSync(
    hook,
    `#!/bin/sh\nexec node "$(git rev-parse --show-toplevel)/scripts/autopilot/guard.mjs" --commit-msg "$1"\n`,
  );
  chmodSync(hook, 0o755);
  console.log(`guard: installed ${hook}`);
}

function snapshot() {
  const files = expand(CFG.never);
  const out = files.map((p) => `${sha(join(MAIN_ROOT, p))}  ${p}`);
  writeFileSync(HASHES, out.join('\n') + '\n');
  console.log(`guard: snapshot of ${out.length} protected files`);
}

function verifyProtected() {
  if (!existsSync(HASHES)) die(`missing ${HASHES} (run --init)`);
  const recorded = new Map(
    lines(readFileSync(HASHES, 'utf8')).map((l) => {
      const i = l.indexOf('  ');
      return [l.slice(i + 2), l.slice(0, i)];
    }),
  );
  for (const [p, h] of recorded) {
    if (!existsSync(p)) errors.push(`protected file deleted: ${p}`);
    else if (sha(p) !== h) errors.push(`protected file changed: ${p}`);
  }
  for (const p of expand(CFG.never))
    if (!recorded.has(p)) errors.push(`new file in a protected path: ${p} (R3: ground truth and snapshots are human-owned)`);
}

function verifyHistory(base, head = 'HEAD') {
  const commits = lines(git('log', '--first-parent', '--format=%H%x09%P%x09%s', `${base}..${head}`));
  const seenTask = new Map();
  const seenSubject = new Map();
  for (const c of commits) {
    const [h, parents, subject] = c.split('\t');
    const short = h.slice(0, 7);
    if (parents.split(' ').length > 1) errors.push(`${short} merge commit on the run branch: "${subject}"`);
    const p = msgProblem(subject);
    if (p) errors.push(`${short} ${p}`);
    if (seenSubject.has(subject)) errors.push(`${short} duplicate of ${seenSubject.get(subject)}: "${subject}"`);
    seenSubject.set(subject, short);
    const id = taskId(subject);
    if (id && seenTask.has(id))
      errors.push(`${short} second commit for ${id} (first: ${seenTask.get(id)}). Fold it in with --fixup + autosquash`);
    if (id && !seenTask.has(id)) seenTask.set(id, short);
  }
  return { commits: commits.length, tasks: seenTask.size };
}

const proposedLines = (text) =>
  text
    .split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /\[PROPOSED\b/.test(l));

function verifyApproval() {
  if (!existsSync(APPROVAL)) {
    errors.push('SPEC is not approved for this run (a person runs --approve-spec)');
    return;
  }
  const a = loadJson(APPROVAL);
  if (a.sha !== sha(join(MAIN_ROOT, SPEC)))
    errors.push(`${SPEC} changed since approval at ${a.approvedAt}; build stops until a person re-approves`);
}

// Card anchors: "### Heading" selects that section; any other string selects every SPEC line containing it.
function specHaystack(spec, anchors, cardId) {
  const L = spec.split('\n');
  const out = [];
  for (const a of anchors) {
    if (a.startsWith('#')) {
      const level = a.match(/^#+/)[0].length;
      const start = L.findIndex((l) => l.trim() === a.trim());
      if (start < 0) {
        errors.push(`${cardId}: SPEC anchor not found: ${a}`);
        continue;
      }
      if (/\[\s*X\s*\]/i.test(L[start])) errors.push(`${cardId}: ${a} is marked [X] done; done phases are never redone (R25)`);
      const end = L.findIndex((l, i) => i > start && /^#{1,6}\s/.test(l) && l.match(/^#+/)[0].length <= level);
      out.push(...L.slice(start, end < 0 ? L.length : end));
    } else {
      const hit = L.filter((l) => l.includes(a));
      if (!hit.length) errors.push(`${cardId}: SPEC anchor not found: ${a}`);
      out.push(...hit);
    }
  }
  return out.join('\n');
}

function numberForms(n) {
  const s = String(n);
  if (!Number.isInteger(n)) return [s];
  const comma = n.toLocaleString('en-US');
  return [...new Set([s, comma, comma.replace(/,/g, ' '), comma.replace(/,/g, '_')])];
}

function checkCard(card, spec) {
  const anchors = card.spec ?? [];
  if (!anchors.length) {
    errors.push(`${card.id}: card.spec lists no SPEC anchors`);
    return;
  }
  const hay = specHaystack(spec, anchors, card.id);
  for (const [k, raw] of Object.entries(card.defaults ?? {})) {
    const entry = raw !== null && typeof raw === 'object' ? raw : { value: raw };
    if (typeof entry.value !== 'number' && entry.spec === undefined) continue;
    const forms = entry.spec !== undefined ? [String(entry.spec)] : numberForms(entry.value);
    const found = forms.some((f) => new RegExp(`(^|[^0-9.])${esc(f)}([^0-9]|$)`).test(hay));
    if (!found) errors.push(`${card.id}: default ${k}=${forms[0]} is not in its SPEC rows (${anchors.join(' | ')})`);
  }
  // R11: every new feature is behind exactly one experimental flag named in its SPEC rows.
  if (card.flag === undefined) errors.push(`${card.id}: card.flag is required (a FULLSHIELD_EXPERIMENTAL_* name, or null)`);
  else if (card.flag !== null) {
    if (!/^FULLSHIELD_EXPERIMENTAL_[A-Z0-9_]+$/.test(card.flag)) errors.push(`${card.id}: bad flag "${card.flag}"`);
    else if (!hay.includes(card.flag)) errors.push(`${card.id}: flag ${card.flag} is not in its SPEC rows`);
  } else if (!/flag:\s*none|no flag|stable change approved/i.test(hay))
    errors.push(`${card.id}: flag is null but its SPEC rows do not say "Flag: none" (R11)`);
  // R10: a stable-output change is planned only when the SPEC says the human approved it.
  if (card.stableChange === true && !/R10 approved/i.test(hay))
    errors.push(`${card.id}: stableChange is true but its SPEC rows do not say "R10 approved"`);
  const owns = card.owns ?? {};
  for (const f of owns.tests ?? []) if (!isTestFile(f)) errors.push(`${card.id}: owns.tests entry is not under test/: ${f}`);
  for (const f of owns.code ?? []) {
    if (isTestFile(f)) errors.push(`${card.id}: owns.code entry is a test path: ${f}`);
    if (inAny(f, [...CFG.never, ...CFG.masterOnly])) errors.push(`${card.id}: owns a protected or master-only path: ${f}`);
  }
  for (const f of owns.tests ?? [])
    if (inAny(f, [...CFG.never, ...CFG.masterOnly])) errors.push(`${card.id}: owns a protected or master-only path: ${f}`);
  if (!card.done_when) errors.push(`${card.id}: card has no done_when`);
}

function runDocVersionCheck() {
  const script = join(MAIN_ROOT, 'scripts', 'doc-version-check.mjs');
  if (!existsSync(script)) {
    warnings.push('scripts/doc-version-check.mjs not found; skipped');
    return;
  }
  try {
    execFileSync(process.execPath, [script, '--root', process.cwd()], { stdio: 'pipe', encoding: 'utf8' });
  } catch (e) {
    errors.push(`doc-version-check failed:\n    ${String(e.stderr || e.stdout).trim().split('\n').join('\n    ')}`);
  }
}

function addedLines(base, pathspec) {
  return lines(git('diff', '-U0', `${base}...HEAD`, '--', ...pathspec))
    .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
    .map((l) => l.slice(1));
}
const collect = (text, re) => [...new Set([...text.matchAll(re)].map((m) => m[1] ?? m[0]))];

function verifyDocs() {
  const pkg = loadJson(PKG);
  const v = pkg.version;
  runDocVersionCheck();
  const cl = existsSync(CHANGELOG) ? readFileSync(CHANGELOG, 'utf8') : '';
  const top = cl.match(/^##\s+(.+)$/m)?.[1]?.trim() ?? 'missing';
  if (!top.startsWith(`${v} `) && top !== v)
    errors.push(`${CHANGELOG}: top entry is "${top}"; the package is ${v} (rename "Unreleased" at the version bump)`);
  const topEntry = cl.split(/^##\s+/m)[1] ?? '';
  for (const f of CFG.docs.mustMentionVersion) {
    if (!existsSync(f)) errors.push(`missing ${f}`);
    else if (!readFileSync(f, 'utf8').includes(v)) errors.push(`${f} does not mention the current version ${v}`);
  }
  if (!gitOk('rev-parse', '--verify', '--quiet', BASE)) {
    warnings.push(`base ${BASE} not found; run-scoped doc checks skipped`);
    return;
  }
  // 42.1 item 6: docs in the same run as the code.
  const src = addedLines(BASE, ['src']).join('\n');
  for (const id of collect(src, RULE_ID_RE)) {
    if (fileAt(BASE, `rules/${id}.md`) !== null) continue;
    if (!existsSync(`rules/${id}.md`)) errors.push(`new rule ${id}: rules/${id}.md is missing`);
    if (!topEntry.includes(id)) errors.push(`new rule ${id}: not in the ${v} CHANGELOG entry`);
  }
  const errorsDoc = existsSync(CFG.docs.errorsDoc) ? readFileSync(CFG.docs.errorsDoc, 'utf8') : '';
  const baseErrors = fileAt(BASE, CFG.docs.errorsDoc) ?? '';
  for (const code of collect(src, ERR_CODE_RE))
    if (!baseErrors.includes(code) && !errorsDoc.includes(code)) errors.push(`new error code ${code}: not in ${CFG.docs.errorsDoc}`);
  const flagDoc = existsSync(CFG.docs.flagDoc) ? readFileSync(CFG.docs.flagDoc, 'utf8') : '';
  for (const f of collect(src, FLAG_RE)) {
    if (gitOk('grep', '-q', f, BASE, '--', 'src')) continue; // not new in this run
    if (!flagDoc.includes(f)) errors.push(`flag ${f} used in new src lines: not in ${CFG.docs.flagDoc}`);
    if (!topEntry.includes(f)) errors.push(`new flag ${f}: not in the ${v} CHANGELOG entry`);
  }
}

function verifyNoLogs() {
  for (const f of existsSync(STATE_DIR) ? readdirSync(STATE_DIR) : [])
    if (!STATE_ALLOWED.has(f)) errors.push(`${STATE}${f} is not guard state; run notes stay in memory (AUTOPILOT.md 1a)`);
  const cards = join(STATE_DIR, 'cards');
  for (const f of existsSync(cards) ? readdirSync(cards) : [])
    if (!f.endsWith('.json')) errors.push(`${STATE}cards/${f} is not a card`);
  if (existsSync(join(MAIN_ROOT, 'docs/proposals'))) errors.push('docs/proposals/ exists; proposals stay in memory');
  // Tracked .log files that predate the run (test/fixtures/host/*.log) are fixtures, not run logs.
  for (const f of lines(git('-C', MAIN_ROOT, 'ls-files', '-o', '--exclude-standard')))
    if (/\.log$/i.test(f)) errors.push(`${f}: log file in the tree`);
  if (gitOk('rev-parse', '--verify', '--quiet', BASE))
    for (const f of lines(git('diff', '--name-only', '--diff-filter=A', `${BASE}...HEAD`))) {
      if (inAny(f, CFG.noAddDuringRun)) errors.push(`${f}: run record added to the tree (R26: the run leaves no report file)`);
      else if (/\.log$/i.test(f) && !isFixture(f)) errors.push(`${f}: log file added in the run`);
    }
}

function verifyRelease(v) {
  const rel = `release/${v}`;
  if (!branchExists(rel)) {
    errors.push(`no branch ${rel} (run --squash)`);
    return;
  }
  if (!gitOk('merge-base', '--is-ancestor', BASE, rel))
    errors.push(`${rel} is not based on the current ${BASE}; rebase the run branch and re-run --squash`);
  const n = lines(git('rev-list', `${BASE}..${rel}`)).length;
  if (n !== 1) errors.push(`${rel} has ${n} commits on top of ${BASE}; want exactly 1`);
  const subject = git('log', '-1', '--format=%s', rel);
  if (subject !== `release: ${v}`) errors.push(`${rel} subject is "${subject}"; want "release: ${v}"`);
  if (/^Co-authored-by:.*\b(cursor|agent|bot|claude)\b/im.test(git('log', '-1', '--format=%b', rel)))
    errors.push(`${rel} carries an agent co-author trailer`);
  try {
    const pv = readJsonAt(rel, PKG).version;
    if (pv !== v) errors.push(`${PKG} on ${rel} is ${pv}; want ${v}`);
  } catch {
    errors.push(`${PKG} missing on ${rel}`);
  }
  try {
    const lock = readJsonAt(rel, 'package-lock.json');
    const lv = [lock.version, lock.packages?.['']?.version];
    if (lv.some((x) => x !== v)) errors.push(`package-lock.json has ${lv.join('/')}; want ${v} (npm install --package-lock-only)`);
  } catch {
    errors.push(`package-lock.json missing on ${rel}`);
  }
  const cl = fileAt(rel, CHANGELOG);
  if (cl === null) errors.push(`${CHANGELOG} missing on ${rel}`);
  else if (cl.match(/^##\s+(\S+)/m)?.[1] !== v) errors.push(`${CHANGELOG} on ${rel}: top entry is not "## ${v}"`);
  if (git('tag', '-l', `v${v}`)) errors.push(`tag v${v} already exists (R17: never reuse a version)`);
}

// Mutants for FullShield source. Applied in a throwaway worktree, never in the working tree (D14).
function mutants(src, cardFlag) {
  const out = [];
  const report = src.indexOf('ctx.report(');
  if (report >= 0)
    out.push(['first ctx.report removed', src.slice(0, report) + 'void(' + src.slice(report + 'ctx.report('.length)]);
  if (cardFlag) {
    const re = new RegExp(`process\\.env\\.${cardFlag}\\s*===\\s*['"]1['"]`);
    const m = src.match(re);
    if (m) {
      out.push(['flag forced on', src.slice(0, m.index) + 'true' + src.slice(m.index + m[0].length)]);
      out.push(['flag forced off', src.slice(0, m.index) + 'false' + src.slice(m.index + m[0].length)]);
    }
  }
  const flip = { '>': '<=', '>=': '<', '<': '>=', '<=': '>' };
  const fn = src.search(/\bfunction\b|=>\s*\{/);
  const re = /(\s)(>=|<=|>|<)(\s)/g;
  re.lastIndex = Math.max(0, fn);
  const m = re.exec(src);
  if (m) {
    const at = m.index + 1;
    out.push([`flip first "${m[2]}"`, src.slice(0, at) + flip[m[2]] + src.slice(at + m[2].length)]);
  }
  // A boolean return built from a comparison, forced to true: kills only if a negative or
  // below-threshold test exists.
  const cmpRe = /\breturn [^;\n]*(?:>=|<=|===|!==|[^=>]>|<[^=])[^;\n]*;/g;
  for (const m of [...src.matchAll(cmpRe)].filter((x) => !x[0].includes('process.env')).slice(0, 6)) {
    const line = src.slice(0, m.index).split('\n').length;
    out.push([`comparison return on line ${line} forced true`, src.slice(0, m.index) + 'return true;' + src.slice(m.index + m[0].length)]);
  }
  const ret = src.match(/\breturn true;/);
  if (ret) out.push(['first "return true" -> false', src.slice(0, ret.index) + 'return false;' + src.slice(ret.index + 12)]);
  return out;
}

function report(okMsg = 'guard: OK') {
  for (const w of warnings) console.warn(`guard: warning: ${w}`);
  if (errors.length) {
    console.error(`guard: FAIL (${errors.length})\n  - ` + errors.join('\n  - '));
    process.exit(1);
  }
  console.log(okMsg);
  process.exit(0);
}

// ---------------------------------------------------------------- hook
if (flag('--install-hooks')) {
  installHooks();
  process.exit(0);
}

if (flag('--commit-msg')) {
  const branch = currentBranch();
  if (!/^(run|release)\//.test(branch)) process.exit(0); // next, main, wk/*, detached rebase: not policed
  const msgFile = opt('--commit-msg');
  const msg = readFileSync(msgFile, 'utf8');
  const stripped = stripTrailers(msg);
  if (stripped !== msg) writeFileSync(msgFile, stripped);
  const subject = stripped.split('\n')[0].trim();
  if (branch.startsWith('run/') && /^(fixup|amend)! /.test(subject)) process.exit(0);
  const p = msgProblem(subject, branch);
  if (p) {
    console.error(`guard: commit rejected on ${branch}: ${p}`);
    process.exit(1);
  }
  process.exit(0);
}

// ---------------------------------------------------------------- init
if (flag('--init')) {
  const run = need('--run');
  const v = needVersion();
  if (!/^[\w.-]+$/.test(run)) die(`bad run name "${run}"`);
  if (!existsSync(PROTECTED)) die(`missing ${PROTECTED}. Copy the one from AUTOPILOT.md section 2 first`);
  const ignored = existsSync('.gitignore') ? readFileSync('.gitignore', 'utf8').split('\n').map((s) => s.trim()) : [];
  const missing = REQUIRED_IGNORES.filter((l) => !ignored.includes(l));
  if (missing.length) die(`.gitignore lacks ${missing.join(', ')}. A person adds and commits them on ${BASE} first`);
  if (!existsSync(SPEC) || !readFileSync(SPEC, 'utf8').includes(CFG.amendmentMarker))
    die(`${SPEC} has no "${CFG.amendmentMarker}" amendment. A person adds AUTOPILOT.md Appendix A to the SPEC first (R1)`);
  if (!cleanTree()) die(`uncommitted changes; start from a clean ${BASE}`);
  if (!branchExists(BASE)) die(`no local ${BASE} branch`);
  if (gitOk('rev-parse', '--verify', '--quiet', `origin/${BASE}`) && git('rev-parse', BASE) !== git('rev-parse', `origin/${BASE}`))
    die(`${BASE} differs from origin/${BASE}; a person fetches and fast-forwards it first`);
  if (currentBranch() !== BASE) die(`check out ${BASE} first`);
  const cur = loadJson(PKG).version;
  if (cmpVer(v, cur) <= 0) die(`--version ${v} is not above the current ${cur} (R17)`);
  if (git('tag', '-l', `v${v}`)) die(`tag v${v} already exists (R17)`);
  installHooks();
  mkdirSync(CARDS, { recursive: true });
  snapshot();
  if (!branchExists(`run/${run}`)) git('branch', `run/${run}`, BASE);
  rmSync(APPROVAL, { force: true });
  if (!existsSync(RUN_STATE))
    writeFileSync(
      RUN_STATE,
      [
        `RUN ${run}   VERSION ${v}   BASE ${BASE} ${git('rev-parse', '--short', BASE)}   MODE <A|B>`,
        'PHASE spec',
        'SPEC APPROVED no',
        'TASKS',
        'OPEN QUESTIONS',
        'DECISIONS',
        `NEXT ACTION write the version ${v} scope into ${SPEC}`,
        '',
      ].join('\n'),
    );
  console.log(`guard: run ${run} for ${v} initialised on run/${run} (from ${BASE})`);
  process.exit(0);
}

// ---------------------------------------------------------------- spec approval (person only)
if (flag('--approve-spec')) {
  const run = need('--run');
  if (!process.stdin.isTTY || !process.stdout.isTTY) die('--approve-spec must be run by a person in a terminal, not by an agent');
  const open = proposedLines(readFileSync(SPEC, 'utf8'));
  if (open.length)
    die(
      `SPEC still has ${open.length} [PROPOSED] mark(s). Accept, edit or delete each one:\n  ` +
        open.map(([n, l]) => `${SPEC}:${n} ${l.trim().slice(0, 100)}`).join('\n  '),
    );
  const h = sha(SPEC);
  process.stdout.write(`Approve ${SPEC} (sha ${h.slice(0, 12)}) for run ${run}? Type APPROVE: `);
  const buf = Buffer.alloc(1);
  let answer = '';
  for (;;) {
    let n = 0;
    try {
      n = readSync(0, buf, 0, 1, null);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;
      throw e;
    }
    if (!n || buf[0] === 10) break;
    answer += buf.toString();
  }
  if (answer.trim() !== 'APPROVE') die('not approved');
  writeFileSync(
    APPROVAL,
    JSON.stringify({ run, sha: h, approvedAt: new Date().toISOString(), by: process.env.USER ?? null }, null, 2) + '\n',
  );
  console.log(`guard: SPEC approved for run ${run}`);
  process.exit(0);
}

if (flag('--verify-spec')) {
  verifyApproval();
  const spec = readFileSync(SPEC, 'utf8');
  for (const [n, l] of proposedLines(spec)) errors.push(`${SPEC}:${n} still [PROPOSED]: ${l.trim().slice(0, 80)}`);
  const id = opt('--card');
  const ids = id
    ? [id]
    : existsSync(CARDS)
      ? readdirSync(CARDS)
          .filter((f) => f.endsWith('.json'))
          .map((f) => f.slice(0, -5))
      : [];
  for (const c of ids) checkCard(loadCard(c), spec);
  report(`guard: spec OK (${ids.length} card(s) checked)`);
}

// ---------------------------------------------------------------- mutation check
if (flag('--mutate')) {
  const card = loadCard(need('--card'));
  if (!card.done_when) die(`${card.id}: card has no done_when`);
  const skip = new Set(card.mutantsSkip ?? []);
  const top = git('rev-parse', '--show-toplevel');
  const owned = (card.owns?.code ?? []).filter((f) => !f.includes('*') && /\.(ts|[cm]?js)$/.test(f) && existsSync(f));
  // The flag check may live in a shared helper (src/**/experimental.ts); mutate it there too.
  let flagHome = [];
  if (card.flag && gitOk('grep', '-q', `process.env.${card.flag}`, '--', 'src'))
    flagHome = lines(git('grep', '-l', `process.env.${card.flag}`, '--', 'src')).filter((f) => !owned.includes(f));
  const targets = [...owned, ...flagHome];
  if (!targets.length) die(`${card.id}: no code file to mutate`);
  if (!cleanTree()) die('uncommitted changes; mutants run against the committed code branch');
  const tmp = mkdtempSync(join(tmpdir(), `fs-mutate-${card.id}-`));
  const wt = join(tmp, 'tree');
  const cleanup = () => {
    gitOk('worktree', 'remove', '--force', wt);
    gitOk('worktree', 'prune');
    rmSync(tmp, { recursive: true, force: true });
  };
  process.on('SIGINT', () => {
    cleanup();
    process.exit(130);
  });
  try {
    git('worktree', 'add', '--detach', wt, 'HEAD');
    const nm = join(top, 'node_modules');
    if (existsSync(nm) && !existsSync(join(wt, 'node_modules'))) symlinkSync(nm, join(wt, 'node_modules'), 'junction');
  } catch (e) {
    cleanup();
    die(`could not prepare the mutation worktree: ${e.message}`);
  }
  const timeout = (card.timebox_min ?? 45) * 60e3;
  const passes = () => {
    try {
      execSync(card.done_when, { cwd: wt, stdio: 'pipe', shell: '/bin/sh', timeout });
      return true;
    } catch {
      return false;
    }
  };
  let killed = 0;
  let total = 0;
  try {
    if (!passes()) {
      errors.push(`${card.id}: done_when fails on the unmutated code; nothing to measure`);
    } else {
      for (const f of targets) {
        const abs = join(wt, f);
        const src = readFileSync(abs, 'utf8');
        const list = owned.includes(f) ? mutants(src, card.flag) : mutants(src, card.flag).filter(([l]) => l.startsWith('flag'));
        for (const [label, mutant] of list) {
          if (skip.has(label)) continue;
          total++;
          writeFileSync(abs, mutant);
          const survived = passes();
          writeFileSync(abs, src);
          if (survived) errors.push(`${f}: mutant "${label}" survived; the tests do not pin this behavior`);
          else killed++;
        }
      }
      if (!total) errors.push(`${card.id}: no mutant generated; the reviewer mutates by hand and records it in ${CFG.decisions}`);
    }
  } finally {
    cleanup();
  }
  report(`guard: mutants killed ${killed}/${total}`);
}

// ---------------------------------------------------------------- protected, history, docs, logs
if (flag('--verify-protected')) {
  verifyProtected();
  report();
}

if (flag('--verify-history')) {
  const { commits, tasks } = verifyHistory(BASE);
  report(`guard: history OK (${commits} commits, ${tasks} tasks)`);
}

if (flag('--verify-no-logs')) {
  verifyNoLogs();
  report('guard: no run logs');
}

if (flag('--verify-docs')) {
  verifyDocs();
  report('guard: docs OK');
}

// ---------------------------------------------------------------- squash into one release commit
if (flag('--squash')) {
  const run = need('--run');
  const v = needVersion();
  const runBranch = `run/${run}`;
  const rel = `release/${v}`;
  if (!cleanTree()) die('uncommitted changes');
  if (!branchExists(runBranch)) die(`no branch ${runBranch}`);
  if (branchExists(rel)) die(`${rel} already exists; delete it first if this is a redo`);
  if (!gitOk('merge-base', '--is-ancestor', BASE, runBranch))
    die(`${runBranch} is not on top of ${BASE}; rebase it and re-run the gate first`);
  verifyHistory(BASE, runBranch);
  verifyProtected();
  verifyApproval();
  verifyNoLogs();
  const pv = readJsonAt(runBranch, PKG).version;
  if (pv !== v) errors.push(`${PKG} on ${runBranch} is ${pv}; want ${v}`);
  if (errors.length) report();
  const subjects = lines(git('log', '--reverse', '--first-parent', '--format=%s', `${BASE}..${runBranch}`));
  if (!subjects.length) die(`${runBranch} has no commits on top of ${BASE}`);
  git('checkout', '-b', rel, BASE);
  git('merge', '--squash', runBranch);
  const msgDir = mkdtempSync(join(tmpdir(), 'fs-release-'));
  const msgPath = join(msgDir, 'msg.txt');
  writeFileSync(msgPath, `release: ${v}\n\n${subjects.map((s) => `- ${s}`).join('\n')}\n`);
  git('commit', '-F', msgPath);
  rmSync(msgDir, { recursive: true, force: true });
  if (git('rev-parse', `${rel}^{tree}`) !== git('rev-parse', `${runBranch}^{tree}`))
    errors.push(`${rel} tree differs from ${runBranch}`);
  verifyRelease(v);
  report(`guard: ${rel} holds one commit for ${subjects.length} task commit(s)`);
}

if (flag('--verify-release')) {
  verifyRelease(needVersion());
  report('guard: release branch OK');
}

// ---------------------------------------------------------------- release check (read-only)
if (flag('--release-check')) {
  const v = needVersion();
  verifyRelease(v);
  const blockers = errors.splice(0);
  const rel = `release/${v}`;
  const ref = branchExists(rel) ? rel : 'HEAD';
  const pkg = readJsonAt(ref, PKG);
  if (pkg.repository?.url !== 'git+https://github.com/kathanp/fullshield.git')
    blockers.push(`${PKG}: repository.url must be git+https://github.com/kathanp/fullshield.git or provenance fails`);
  if (!pkg.license) blockers.push(`${PKG}: no "license"`);
  for (const k of ['bugs', 'homepage']) if (!pkg[k]) warnings.push(`${PKG}: no "${k}" (not required for provenance)`);
  const lastTag = lines(git('tag', '--list', 'v*', '--sort=-v:refname'))[0];
  if (lastTag) {
    const before = Object.keys(readJsonAt(lastTag, PKG).dependencies ?? {});
    for (const d of Object.keys(pkg.dependencies ?? {}))
      if (!before.includes(d)) blockers.push(`${PKG}: new runtime dependency "${d}" since ${lastTag} (R13)`);
  } else warnings.push('no v* tag found locally; R13 dependency check skipped (git fetch --tags)');
  const security = fileAt(ref, 'SECURITY.md') ?? '';
  if (!security.includes(v)) blockers.push(`SECURITY.md: supported-versions table does not mention ${v}`);
  const pub = fileAt(ref, '.github/workflows/publish.yml') ?? '';
  if (!/id-token:\s*write/.test(pub) || !/npm-stage-publish\.mjs/.test(pub) || !/provenance-gate\.mjs/.test(pub))
    blockers.push('publish.yml: needs id-token: write, npm-stage-publish.mjs and provenance-gate.mjs (S6)');
  const pubCode = pub
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');
  if (/secrets\.NPM_TOKEN|NODE_AUTH_TOKEN\s*:/.test(pubCode)) blockers.push('publish.yml: uses a token; trusted publishing only (S6)');
  if (!gitOk('remote', 'get-url', 'origin')) blockers.push('no git remote "origin"');
  console.log(`guard: release check for ${v}`);
  for (const w of warnings) console.log(`WARNING ${w}`);
  if (blockers.length) console.log('BLOCKERS\n  - ' + blockers.join('\n  - '));
  console.log('MANUAL (cannot be checked here)\n  - ' + CFG.releaseManual.join('\n  - '));
  console.log(
    [
      'ORDER (a person runs every step; this script runs none)',
      `  1. git fetch origin && git push origin release/${v}:${BASE}      (fast-forward only; if refused, rebase the run and re-squash)`,
      `  2. wait for CI on ${BASE} (verify, ubuntu, node 24) to go green`,
      `  3. open a PR ${BASE} -> main; the 6 matrix jobs go green; merge with "Create a merge commit" (R18)`,
      `  4. git fetch origin && git tag v${v} origin/main && git push origin v${v}      (R1, R17)`,
      '  5. on npmjs.com approve the staged publish with 2FA within 10 minutes; the Provenance gate job must go green (S6)',
      `  6. stranger check (SPEC Section 2 step 10) with npx fullshield@${v}`,
      `  7. node scripts/autopilot/guard.mjs --cleanup --run <name> --version ${v}`,
    ].join('\n'),
  );
  process.exit(blockers.length ? 1 : 0);
}

// ---------------------------------------------------------------- cleanup
if (flag('--cleanup')) {
  const run = need('--run');
  const v = needVersion();
  const rel = `release/${v}`;
  if (!cleanTree()) die('uncommitted changes; nothing erased');
  if (/^(run|wk|release)\//.test(currentBranch())) die(`check out ${BASE} or main before cleanup`);
  if (!branchExists(rel)) die(`no branch ${rel}; nothing erased`);
  if (!gitOk('rev-parse', '--verify', '--quiet', 'origin/main')) die('no origin/main; run git fetch first');
  if (!gitOk('merge-base', '--is-ancestor', rel, 'origin/main'))
    die(`${rel} is not in origin/main (fetch first; merge the PR with a merge commit). Nothing erased`);
  if (branchExists(`run/${run}`) && git('rev-parse', `${rel}^{tree}`) !== git('rev-parse', `run/${run}^{tree}`))
    die(`${rel} tree differs from run/${run}; nothing erased`);
  const wtRoot = resolve(MAIN_ROOT, CFG.worktreeRoot) + '/';
  let removed = 0;
  for (const l of lines(git('worktree', 'list', '--porcelain')).filter((x) => x.startsWith('worktree '))) {
    const p = resolve(l.slice(9)) + '/';
    if (p.startsWith(wtRoot)) {
      git('worktree', 'remove', '--force', p);
      removed++;
    }
  }
  git('worktree', 'prune');
  const branches = lines(git('for-each-ref', '--format=%(refname:short)', 'refs/heads/wk/', `refs/heads/run/${run}`));
  for (const b of branches) git('branch', '-D', b);
  git('branch', '-D', rel);
  for (const f of existsSync(STATE_DIR) ? readdirSync(STATE_DIR) : [])
    if (f !== 'protected.json') rmSync(join(STATE_DIR, f), { recursive: true, force: true });
  console.log(`guard: run ${run} erased: ${branches.length + 1} branches, ${removed} worktrees, run state`);
  process.exit(0);
}

// ---------------------------------------------------------------- task branch
const id = opt('--card');
const role = opt('--role');
if (!id || !['test', 'code'].includes(role)) die('unknown command. See the header of scripts/autopilot/guard.mjs for usage');

const card = loadCard(id);
verifyApproval();
const base = opt('--base', role === 'code' ? `wk/test/${id}` : card.base);
if (!base) die('pass --base or set "base" (e.g. "run/<name>") in the card');

const status = lines(git('diff', '--name-status', `${base}...HEAD`)).map((l) => {
  const [s, ...rest] = l.split('\t');
  return { s: s[0], f: rest[rest.length - 1], from: rest[0] };
});
const owned = role === 'test' ? [...card.owns.tests, ...card.owns.code] : card.owns.code;

for (const { s, f, from } of status) {
  if (f.startsWith(STATE)) continue;
  if (inAny(f, CFG.never)) errors.push(`touches never-edit file: ${f}`);
  else if (inAny(f, CFG.masterOnly)) errors.push(`touches master-only file: ${f} (put it in master_edits instead)`);
  else if (role === 'code' && isTestFile(f)) errors.push(`code agent edited a test or fixture: ${f}`);
  else if (!inAny(f, owned)) errors.push(`outside card ownership (${role}): ${f}`);
  if (s === 'D' && isTestFile(f)) errors.push(`R3: test or fixture deleted: ${f}`);
  if (s === 'R' && isTestFile(from)) errors.push(`R3: test or fixture renamed: ${from} -> ${f}`);
}

// R3: an existing test or fixture may gain lines, never lose or change one.
for (const { s, f } of status.filter((x) => x.s === 'M' && isTestFile(x.f))) {
  const removed = lines(git('diff', '-U0', `${base}...HEAD`, '--', f)).filter((l) => l.startsWith('-') && !l.startsWith('---'));
  if (removed.length) errors.push(`R3: ${removed.length} line(s) removed or changed in existing ${f} (${s})`);
}

const banned = [
  [/\bDate\.now\s*\(/, 'Date.now()'],
  [/\bMath\.random\s*\(/, 'Math.random()'],
  [/\.(only|skip)\s*\(|\{\s*(only|skip)\s*:\s*true/, '.only/.skip'],
  [/\bit\.todo\s*\(|\btest\.todo\s*\(|\btodo\s*:\s*true/, 'todo test'],
  [/\b(xit|xdescribe|xtest)\s*\(/, 'xit/xdescribe'],
];
// Spec section 13: fake credentials are built by concatenation, never one realistic literal.
const secretLiterals = [
  [/AKIA[0-9A-Z]{16}/, 'AWS key literal'],
  [/sk_live_[0-9a-zA-Z]{16,}/, 'Stripe live key literal'],
  [/gh[pousr]_[A-Za-z0-9]{36}/, 'GitHub token literal'],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/, 'Slack token literal'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'PEM private key literal'],
];
for (const { f } of status.filter((x) => x.s !== 'D' && isTestFile(x.f) && existsSync(x.f))) {
  const added = addedLines(base, [f]);
  added.forEach((l, i) => {
    if (!isFixture(f))
      for (const [re, name] of banned) if (re.test(l)) errors.push(`${name} in ${f}: ${l.trim().slice(0, 80)}`);
    for (const [re, name] of secretLiterals) if (re.test(l)) errors.push(`${name} in ${f} (build it by concatenation, spec 13)`);
    if (/\.skipIf\s*\(/.test(l) && !/\/\/|\/\*/.test(l) && !/\/\/|\/\*/.test(added[i - 1] ?? ''))
      errors.push(`skipIf without a reason comment in ${f} (R22): ${l.trim().slice(0, 80)}`);
  });
  if (!isFixture(f) && /\.test\.[cm]?[jt]s$/.test(f) && !/\bexpect\s*\(|\bassert\b/.test(readFileSync(f, 'utf8')))
    errors.push(`${f}: test file with no expect( (anti-cheat)`);
}

// Source: no fake implementations (R5), no flag other than the card's (R11).
const srcAdded = addedLines(base, ['src']);
for (const l of srcAdded) {
  if (/TODO: implement|throw new Error\(\s*['"`]Not implemented/i.test(l)) errors.push(`stub in src (R5): ${l.trim().slice(0, 80)}`);
  for (const fl of l.match(FLAG_RE) ?? [])
    if (fl !== card.flag && !gitOk('grep', '-q', fl, base, '--', 'src')) errors.push(`src adds a new flag ${fl}; this card's flag is ${card.flag ?? 'none'} (R11: one flag per phase)`);
}

report();
