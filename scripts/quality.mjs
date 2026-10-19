#!/usr/bin/env node
/**
 * Phase 94 quality gate. Prints one table: check | scope | result | count | baseline.
 * Existing violations live in quality/baseline.json. New ones fail. Counts only go down.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptRoot = dirname(dirname(fileURLToPath(import.meta.url)));

function argValue(flag, fallback) {
  const index = process.argv.indexOf(flag);
  if (index === -1) return fallback;
  return process.argv[index + 1] ?? fallback;
}

const root = argValue('--root', scriptRoot);
const fixture = process.argv.includes('--fixture');
const writeBaseline = process.argv.includes('--write-baseline');
const baseRef = argValue('--base', 'next');

function parseFirstJson(text, label) {
  const start = text.search(/[[{]/);
  if (start < 0) throw new Error(`${label} produced no JSON`);
  const slice = text.slice(start);
  try {
    return JSON.parse(slice);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const position = message.match(/position (\d+)/);
    if (position === null || !message.includes('after JSON')) throw new Error(`${label}: ${message}`);
    return JSON.parse(slice.slice(0, Number(position[1])));
  }
}

function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function listFiles(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'dist', 'coverage', '.git'].includes(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) listFiles(full, out);
    else out.push(full);
  }
  return out;
}

function git(args) {
  return spawnSync('git', args, { cwd: root, encoding: 'utf8' });
}

function changedSrcFiles() {
  const result = git(['diff', '--name-only', `${baseRef}...HEAD`, '--', 'src']);
  if (result.status !== 0) return [];
  return result.stdout.split('\n').map((line) => line.trim()).filter((line) => line.endsWith('.ts'));
}

/** Counted by Q1/Q2. Never rewritten by this script. */
const RULE_NO_AUTOFIX = ['src/modules/sast/rules/', 'src/modules/secrets/rules/'];

function runEslint(files) {
  if (files.length === 0) return [];
  if (RULE_NO_AUTOFIX.length === 0) throw new Error('rule files must stay out of Q1 autofix');
  const eslint = join(scriptRoot, 'node_modules', 'eslint', 'bin', 'eslint.js');
  const config = join(scriptRoot, 'quality', 'eslint.config.mjs');
  const args = [eslint, '-c', config, '--format', 'json', ...files];
  if (args.includes('--fix')) throw new Error('quality does not autofix rule files');
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, QUALITY_ROOT: root, QUALITY_TYPED: fixture ? '0' : '1' },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.stdout.trim() === '') {
    throw new Error(`eslint produced no JSON: ${result.stderr}`);
  }
  return parseFirstJson(result.stdout, 'eslint');
}

function messageCount(report, relPath) {
  const row = report.find((item) => relative(root, item.filePath).split(sep).join('/') === relPath);
  if (row === undefined) return 0;
  return row.messages.filter((message) => message.severity === 2).length;
}

function knipKeys() {
  const bin = join(scriptRoot, 'node_modules', 'knip', 'dist', 'cli.js');
  const result = spawnSync(process.execPath, [
    bin,
    '--directory', root,
    '--reporter', 'json',
    '--no-progress',
    '--no-exit-code',
    '--include', 'files,exports,dependencies',
  ], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (!result.stdout.includes('{')) throw new Error(`knip produced no JSON: ${result.stderr}`);
  const parsed = parseFirstJson(result.stdout, 'knip');
  const keys = [];
  for (const issue of parsed.issues ?? []) {
    const file = String(issue.file).split(sep).join('/');
    for (const row of issue.files ?? []) keys.push(`file:${row.name ?? file}`);
    for (const row of issue.exports ?? []) keys.push(`export:${file}:${row.name}`);
    for (const row of issue.devDependencies ?? []) keys.push(`devDep:${row.name}`);
    for (const row of issue.dependencies ?? []) keys.push(`dep:${row.name}`);
  }
  return [...new Set(keys)].sort();
}

function srcTextFiles() {
  return listFiles(join(root, 'src')).filter((file) => file.endsWith('.ts'));
}

function lineHits(pattern) {
  const hits = [];
  for (const file of srcTextFiles()) {
    const rel = relative(root, file).split(sep).join('/');
    const lines = readFileSync(file, 'utf8').split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      if (pattern.test(lines[i])) hits.push(`${rel}:${lines[i].trim()}`);
    }
    pattern.lastIndex = 0;
  }
  return hits.sort();
}

function documentedCodes() {
  const path = join(root, 'docs', 'errors.md');
  if (!existsSync(path)) return new Set();
  return new Set(readFileSync(path, 'utf8').match(/FS-E\d+/g) ?? []);
}

function usedCodes() {
  const codes = new Set();
  for (const file of srcTextFiles()) {
    for (const match of readFileSync(file, 'utf8').matchAll(/FS-E\d+/g)) codes.add(match[0]);
  }
  return [...codes].sort();
}

const DANGEROUS = [
  [/from\s+['"]node:child_process['"]|require\(\s*['"]node:child_process['"]\s*\)|require\(\s*['"]child_process['"]\s*\)/, 'child_process'],
  [/\beval\s*\(/, 'eval'],
  [/new\s+Function\s*\(/, 'new Function'],
  [/from\s+['"]node:vm['"]|require\(\s*['"]node:vm['"]\s*\)/, 'vm'],
  [/process\.binding\s*\(/, 'process.binding'],
  [/require\(\s*[^'"\s]/, 'dynamic require'],
];

function dangerousUses() {
  const uses = [];
  for (const file of srcTextFiles()) {
    const rel = relative(root, file).split(sep).join('/');
    const text = readFileSync(file, 'utf8');
    for (const [pattern, api] of DANGEROUS) {
      if (pattern.test(text)) uses.push({ path: rel, api });
      pattern.lastIndex = 0;
    }
  }
  return uses;
}

function literalHosts() {
  const hits = [];
  for (const file of srcTextFiles()) {
    const rel = relative(root, file).split(sep).join('/');
    if (rel === 'src/net/hosts.ts') continue;
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(/https?:\/\/[a-zA-Z0-9._:-]+/g)) {
      hits.push(`${rel}:${match[0]}`);
    }
  }
  return [...new Set(hits)].sort();
}

function disableLines() {
  const hits = [];
  for (const file of srcTextFiles()) {
    const rel = relative(root, file).split(sep).join('/');
    const lines = readFileSync(file, 'utf8').split('\n');
    for (const line of lines) {
      if (!/eslint-disable/.test(line)) continue;
      hits.push({ rel, line: line.trim(), reasoned: /--\s+\S/.test(line) });
    }
  }
  return hits;
}

function addedSrcFiles() {
  const result = git(['diff', '--name-only', '--diff-filter=A', `${baseRef}...HEAD`, '--', 'src']);
  if (result.status !== 0) return [];
  return result.stdout.split('\n').map((line) => line.trim()).filter((line) => line.endsWith('.ts'));
}

function coverageFor(relPath) {
  const summaryPath = join(root, 'coverage', 'coverage-summary.json');
  if (!existsSync(summaryPath)) return undefined;
  const summary = JSON.parse(readFileSync(summaryPath, 'utf8'));
  const key = Object.keys(summary).find((item) => item.endsWith(relPath) || item.endsWith(relPath.split('/').join(sep)));
  return key === undefined ? undefined : summary[key];
}

function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').trim();
}

function ruleIds() {
  const dir = join(root, 'rules');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((name) => name.endsWith('.md') && name !== 'README.md').map((name) => name.replace(/\.md$/, '')).sort();
}

function experimentalFlags() {
  const flags = new Set();
  for (const file of srcTextFiles()) {
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(/FULLSHIELD_EXPERIMENTAL_[A-Z0-9_]+/g)) flags.add(match[0]);
  }
  return [...flags].sort();
}

function cliHelp() {
  const cli = join(root, 'dist', 'cli', 'index.js');
  if (!existsSync(cli)) return null;
  const top = spawnSync(process.execPath, [cli, '--help'], { cwd: root, encoding: 'utf8' });
  const help = { '': top.stdout };
  const names = [...top.stdout.matchAll(/^\s{2}([a-z][\w-]*)(?:\s|\|)/gm)].map((match) => match[1]);
  for (const name of [...new Set(names)]) {
    const sub = spawnSync(process.execPath, [cli, name, '--help'], { cwd: root, encoding: 'utf8' });
    help[name] = sub.stdout;
  }
  return help;
}

function apiSnapshot() {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const exportsMap = {};
  for (const [key, value] of Object.entries(pkg.exports ?? {})) {
    const types = value && typeof value === 'object' ? value.types : undefined;
    if (typeof types !== 'string') continue;
    const path = join(root, types);
    exportsMap[key] = existsSync(path) ? stripComments(readFileSync(path, 'utf8')) : '';
  }
  return {
    exports: exportsMap,
    help: cliHelp(),
    errorCodes: [...documentedCodes()].sort(),
    ruleIds: ruleIds(),
    flags: experimentalFlags(),
  };
}

function sortedJson(value) {
  return `${JSON.stringify(value, (_key, item) => {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return Object.fromEntries(Object.keys(item).sort().map((key) => [key, item[key]]));
    }
    return item;
  })}\n`;
}

function scanJson(dir, envExtra) {
  const cli = join(root, 'dist', 'cli', 'index.js');
  const result = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, ...envExtra },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.stdout.trim() === '') throw new Error(`scan produced no JSON for ${dir}: ${result.stderr}`);
  const data = JSON.parse(result.stdout);
  if (data.metadata && typeof data.metadata === 'object') {
    delete data.metadata.durationMs;
    delete data.metadata.startedAt;
  }
  if (Array.isArray(data.findings)) {
    data.findings.sort((left, right) => {
      const a = [left.ruleId, left.file, left.line, left.severity, left.id].join('\0');
      const b = [right.ruleId, right.file, right.line, right.severity, right.id].join('\0');
      return a < b ? -1 : a > b ? 1 : 0;
    });
  }
  return sortedJson(data);
}

function packFiles() {
  const result = spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json'], {
    cwd: root,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(result.stderr || 'npm pack failed');
  const parsed = parseFirstJson(result.stdout, 'npm pack');
  const entry = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0];
  return (entry.files ?? []).map((file) => file.path).sort();
}

function row(id, scope, ok, count, baseline) {
  return { id, scope, result: ok ? 'pass' : 'fail', count, baseline };
}

function main() {
  const baselinePath = join(root, 'quality', 'baseline.json');
  const baseline = readJson(baselinePath, {
    q2: {},
    q3: 0,
    q4: [],
    q6Bare: [],
    q6Undocumented: [],
    q7Runtime: [],
    q8: [],
    flags: [],
  });
  const allowPath = join(root, 'quality', 'allowed-dangerous.json');
  const allowed = readJson(allowPath, []);
  const srcFiles = srcTextFiles();
  const report = srcFiles.length === 0 ? [] : runEslint(srcFiles);
  const changed = new Set(changedSrcFiles());
  let q1Count = 0;
  const q2 = {};
  for (const file of srcFiles) {
    const rel = relative(root, file).split(sep).join('/');
    const count = messageCount(report, rel);
    q2[rel] = count;
    if (changed.has(rel)) q1Count += count;
  }
  const q2Baseline = Object.values(baseline.q2 ?? {}).reduce((sum, count) => sum + count, 0);
  const q2Count = Object.values(q2).reduce((sum, count) => sum + count, 0);
  let q2Rise = 0;
  for (const [file, count] of Object.entries(q2)) {
    if (baseline.q2[file] === undefined) continue;
    if (count > baseline.q2[file]) q2Rise += count - baseline.q2[file];
  }
  const disables = disableLines();
  const bareReason = disables.filter((hit) => !hit.reasoned);
  const decisions = existsSync(join(root, 'docs', 'DECISIONS.md'))
    ? readFileSync(join(root, 'docs', 'DECISIONS.md'), 'utf8')
    : '';
  const unlisted = disables.filter((hit) => !decisions.includes(hit.rel));
  const q3Fail = bareReason.length > 0 || disables.length > baseline.q3 || (disables.length > 0 && unlisted.length > 0);
  const q4Now = knipKeys();
  const q4Base = new Set(baseline.q4);
  const q4New = q4Now.filter((key) => !q4Base.has(key));
  const codes = usedCodes();
  const docs = documentedCodes();
  const undocumented = codes.filter((code) => !docs.has(code));
  const knownUndocumented = new Set(baseline.q6Undocumented ?? []);
  const q6UndocNew = undocumented.filter((code) => !knownUndocumented.has(code));
  const bare = lineHits(/throw\s+new\s+Error\s*\(/);
  const bareBase = new Set(baseline.q6Bare);
  const q6BareNew = bare.filter((hit) => !bareBase.has(hit));
  const uses = dangerousUses();
  const allowKey = new Set(allowed.map((item) => `${item.path}:${item.api}`));
  const runtimeBase = new Set(baseline.q7Runtime);
  const q7New = uses.filter((use) => {
    const key = `${use.path}:${use.api}`;
    if (use.path.startsWith('src/runtime')) return !runtimeBase.has(key);
    return !allowKey.has(key);
  });
  const hosts = literalHosts();
  const hostBase = new Set(baseline.q8);
  const q8New = hosts.filter((hit) => !hostBase.has(hit));
  const added = addedSrcFiles();
  const q9Miss = [];
  for (const rel of added) {
    const cov = coverageFor(rel);
    const lines = cov?.lines?.pct ?? 0;
    const branches = cov?.branches?.pct ?? 0;
    if (lines < 90 || branches < 80) q9Miss.push(rel);
  }
  const flags = experimentalFlags();
  const flagBase = new Set(baseline.flags ?? []);
  const newFlags = flags.filter((flag) => !flagBase.has(flag));
  const newRules = ruleIds().filter((id) => !(baseline.ruleIds ?? []).includes(id));

  const rows = [
    row('Q1', 'changed src', q1Count === 0, q1Count, 0),
    row('Q2', 'src', q2Count <= q2Baseline && q2Rise === 0, q2Count, q2Baseline),
    row('Q3', 'eslint-disable', !q3Fail, disables.length, baseline.q3),
    row('Q4', 'knip', q4New.length === 0, q4New.length, baseline.q4.length),
    row('Q6', 'errors', q6UndocNew.length === 0 && q6BareNew.length === 0, q6UndocNew.length + q6BareNew.length, baseline.q6Bare.length),
    row('Q7', 'dangerous APIs', q7New.length === 0, q7New.length, allowed.length + baseline.q7Runtime.length),
    row('Q8', 'network hosts', q8New.length === 0, q8New.length, baseline.q8.length),
  ];

  if (!fixture) {
    const snapPath = join(root, 'api', 'fullshield.api.json');
    const currentApi = apiSnapshot();
    const committed = existsSync(snapPath) ? readFileSync(snapPath, 'utf8') : '';
    const apiText = sortedJson(currentApi);
    rows.push(row('Q5', 'public API', writeBaseline || apiText === committed, writeBaseline ? 0 : Number(apiText !== committed), 0));
    rows.push(row('Q9', 'new file coverage', q9Miss.length === 0, q9Miss.length, 0));
    // Q10 counts new rule ids. It does not rewrite source. The in-place mutator was mutation-smoke.
    rows.push(row('Q10', 'mutation', newRules.length === 0, newRules.length, 0));
    let q11Ok = true;
    if (!writeBaseline) {
      const vuln = join(root, 'test', 'fixtures', 'vulnerable-app');
      const bench = join(homedir(), 'fullshield-bench', 'dvna');
      q11Ok = scanJson(vuln) === scanJson(vuln);
      if (existsSync(bench)) q11Ok = q11Ok && scanJson(bench) === scanJson(bench);
      for (const flag of newFlags) {
        const env = { [flag]: '1' };
        q11Ok = q11Ok && scanJson(vuln, env) === scanJson(vuln, env);
      }
    }
    rows.push(row('Q11', 'determinism', q11Ok, q11Ok ? 0 : 1, 0));
    const packed = packFiles();
    const packPath = join(root, 'quality', 'pack-files.txt');
    const expectedPack = existsSync(packPath) ? readFileSync(packPath, 'utf8').trim().split('\n').filter(Boolean) : [];
    const forbidden = packed.filter((file) => file.endsWith('.map') || /^(test|bench|reports)\//.test(file) || (file.startsWith('scripts/') && !expectedPack.includes(file)));
    const packBudget = spawnSync(process.execPath, [join(scriptRoot, 'scripts', 'pack-budget.mjs')], { cwd: root, encoding: 'utf8' });
    const packSame = writeBaseline || (packed.join('\n') === expectedPack.join('\n') && forbidden.length === 0 && packBudget.status === 0);
    rows.push(row('Q12', 'pack', packSame, forbidden.length, expectedPack.length));
    if (writeBaseline) {
      mkdirSync(dirname(snapPath), { recursive: true });
      mkdirSync(dirname(packPath), { recursive: true });
      writeFileSync(snapPath, apiText);
      writeFileSync(packPath, `${packed.join('\n')}\n`);
    }
  }

  if (writeBaseline) {
    const next = {
      q2,
      q3: disables.length,
      q4: q4Now,
      q6Bare: bare,
      q6Undocumented: undocumented,
      q7Runtime: uses.filter((use) => use.path.startsWith('src/runtime')).map((use) => `${use.path}:${use.api}`).sort(),
      q8: hosts,
      flags,
      ruleIds: ruleIds(),
    };
    mkdirSync(dirname(baselinePath), { recursive: true });
    writeFileSync(baselinePath, `${JSON.stringify(next, null, 2)}\n`);
    const allow = uses
      .filter((use) => !use.path.startsWith('src/runtime'))
      .map((use) => ({
        path: use.path,
        api: use.api,
        reason: 'Existing call recorded in Phase 94. It is not a new execution path.',
      }));
    writeFileSync(allowPath, `${JSON.stringify(allow, null, 2)}\n`);
    for (const item of rows) item.result = 'pass';
  }

  console.log('check\tscope\tresult\tcount\tbaseline');
  for (const item of rows) {
    console.log(`${item.id}\t${item.scope}\t${item.result}\t${item.count}\t${item.baseline}`);
  }
  if (q1Count > 0) console.error(`Q1 files: ${[...changed].join(', ')}`);
  if (q4New.length > 0) console.error(`Q4 new: ${q4New.slice(0, 20).join(', ')}`);
  if (q6UndocNew.length > 0 || q6BareNew.length > 0) console.error(`Q6 new: ${[...q6UndocNew, ...q6BareNew].slice(0, 20).join(', ')}`);
  if (q7New.length > 0) console.error(`Q7 new: ${q7New.map((use) => `${use.path}:${use.api}`).join(', ')}`);
  if (q8New.length > 0) console.error(`Q8 new: ${q8New.slice(0, 20).join(', ')}`);
  if (!fixture) {
    const dirty = spawnSync('git', ['diff', '--exit-code', '--', 'src', 'test'], { cwd: root, encoding: 'utf8' });
    if (dirty.status !== 0) {
      console.error('fullshield: FS-E011 src or test changed during quality');
      console.error(dirty.stdout ?? '');
      process.exit(1);
    }
  }
  if (rows.some((item) => item.result === 'fail')) process.exit(1);
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
}
