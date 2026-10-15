#!/usr/bin/env node
/**
 * Phase 26: clone pinned public apps, scan with the built CLI, score vs ground truth.
 * Clones go to a temp dir and are not committed.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const scorePath = join(root, 'dist', 'bench', 'score.js');
if (!existsSync(scorePath)) {
  console.error('dist/bench/score.js missing; run `npm run build` first');
  process.exit(1);
}

const { BENCH_CLASSES, classForRule, scoreFindings } = await import(pathToFileURL(scorePath).href);

const APPS = [
  {
    id: 'nodegoat',
    repo: 'https://github.com/OWASP/NodeGoat.git',
    sha: 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8',
  },
  {
    id: 'juice-shop',
    repo: 'https://github.com/juice-shop/juice-shop.git',
    sha: 'e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4',
  },
  {
    id: 'dvna',
    repo: 'https://github.com/appsecco/dvna.git',
    sha: '9ba473add536f66ac9007966acb2a775dd31277a',
  },
];

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

function clonePinned(repo, sha, dest) {
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
  const init = spawnSync('git', ['init', dest], { encoding: 'utf8', env });
  if (init.status !== 0) fail(`git init failed: ${init.stderr}`);
  spawnSync('git', ['-C', dest, 'remote', 'add', 'origin', repo], { encoding: 'utf8', env });
  const fetch = spawnSync('git', ['-C', dest, 'fetch', '--depth', '1', 'origin', sha], {
    encoding: 'utf8',
    env,
  });
  if (fetch.status !== 0) fail(`git fetch ${repo} ${sha} failed: ${fetch.stderr}`);
  const co = spawnSync('git', ['-C', dest, 'checkout', '--detach', 'FETCH_HEAD'], {
    encoding: 'utf8',
    env,
  });
  if (co.status !== 0) fail(`git checkout failed: ${co.stderr}`);
}

function loadTruth(id) {
  const path = join(root, 'bench', id, 'ground-truth.json');
  const truth = JSON.parse(readFileSync(path, 'utf8'));
  if (truth.reviewed !== false && truth.reviewed !== true) {
    fail(`${path} must set "reviewed" to true or false`);
  }
  for (const e of truth.entries ?? []) {
    if (!e.source || typeof e.source !== 'string' || !/^https?:\/\//.test(e.source)) {
      fail(`${path} entry missing http(s) source: ${JSON.stringify(e)}`);
    }
    if (!BENCH_CLASSES.includes(e.class)) fail(`${path} bad class ${e.class}`);
  }
  return truth;
}

function scanApp(dir) {
  const cli = join(root, 'dist', 'cli', 'index.js');
  const started = Date.now();
  const r = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  });
  const ms = Date.now() - started;
  const stdout = r.stdout ?? '';
  const jsonStart = stdout.indexOf('{');
  if (jsonStart < 0) {
    return { findings: [], ms, error: r.stderr || stdout.slice(0, 500), status: r.status };
  }
  try {
    const report = JSON.parse(stdout.slice(jsonStart));
    return {
      findings: report.findings ?? [],
      ms,
      status: r.status,
      version: report.metadata?.version,
    };
  } catch (err) {
    return { findings: [], ms, error: String(err), status: r.status };
  }
}

function pct(num, den) {
  if (den === 0) return 'n/a';
  return `${((100 * num) / den).toFixed(1)}%`;
}

function byClass(entries) {
  const map = Object.fromEntries(BENCH_CLASSES.map((c) => [c, 0]));
  for (const e of entries) map[e.class] += 1;
  return map;
}

function findingsByClass(findings) {
  const map = Object.fromEntries(BENCH_CLASSES.map((c) => [c, 0]));
  for (const f of findings) map[classForRule(f.ruleId)] += 1;
  return map;
}

function missWhy(entry) {
  if (/Log injection/i.test(entry.description)) return 'log forging is not a shipped SAST class';
  if (/deserializ/i.test(entry.description)) return 'no SAST-DESER rule in this release (Phase 29)';
  if (/eval|mathjs/i.test(entry.description)) {
    return 'eval/SSJS is class other here; SAST-EVAL may still fire on a nearby line';
  }
  return 'not detected at the documented file/line (±3)';
}

const work = mkdtempSync(join(tmpdir(), 'fullshield-bench-'));
const results = [];
let anyUnreviewed = false;

for (const app of APPS) {
  const truth = loadTruth(app.id);
  if (truth.reviewed === false) anyUnreviewed = true;
  const dest = join(work, app.id);
  mkdirSync(dest, { recursive: true });
  console.error(`cloning ${app.repo} @ ${app.sha}`);
  clonePinned(app.repo, app.sha, dest);
  console.error(`scanning ${app.id}`);
  const scan = scanApp(dest);
  const scored = scoreFindings(scan.findings, truth.entries);
  const tp = scored.truePositives.length;
  const fp = scored.falsePositives.length;
  const miss = scored.misses.length;
  results.push({
    id: app.id,
    sha: app.sha,
    repo: app.repo,
    reviewed: truth.reviewed === true,
    scan,
    scored,
    tp,
    fp,
    miss,
    precision: pct(tp, tp + fp),
    recall: pct(tp, tp + miss),
    truthByClass: byClass(truth.entries),
    tpByClass: byClass(scored.truePositives),
    missByClass: byClass(scored.misses),
    fpByClass: findingsByClass(scored.falsePositives),
  });
}

const knownMisses = [];
for (const r of results) {
  for (const m of r.scored.misses) {
    knownMisses.push({ app: r.id, ...m, why: missWhy(m) });
  }
}

const lines = [];
lines.push('# FullShield public benchmark');
lines.push('');
if (anyUnreviewed) {
  lines.push('> **UNREVIEWED DRAFT.** Every `bench/*/ground-truth.json` still has `"reviewed": false`.');
  lines.push(
    '> Do not cite precision, recall, or headline counts from this file until the human flips that flag.',
  );
  lines.push('');
}
lines.push(`- FullShield version: ${pkg.version}`);
lines.push(`- Generated: ${new Date().toISOString()}`);
lines.push('- Matching: same class + same file, line within ±3');
lines.push('- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`');
lines.push(
  '- False positives = scanner findings that did not match a labeled ground-truth entry. The labeled set is a small cited subset of each app’s documented bugs, so unmatched deps/config/secrets hits count as FP even when they are real issues.',
);
lines.push('');

for (const r of results) {
  lines.push(`## ${r.id}`);
  lines.push('');
  lines.push(`- Repo: ${r.repo}`);
  lines.push(`- Commit: \`${r.sha}\``);
  lines.push(`- Scan time: ${r.scan.ms} ms`);
  lines.push(`- Ground truth reviewed: ${r.reviewed}`);
  if (r.scan.error) lines.push(`- Scan error: ${r.scan.error}`);
  lines.push(`- Findings emitted: ${r.scan.findings.length}`);
  lines.push(`- True positives: ${r.tp}`);
  lines.push(`- False positives: ${r.fp}`);
  lines.push(`- Misses: ${r.miss}`);
  lines.push(`- Precision: ${r.precision}`);
  lines.push(`- Recall: ${r.recall}`);
  lines.push('');
  lines.push('| class | truth | TP | FP | misses |');
  lines.push('|---|---:|---:|---:|---:|');
  for (const c of BENCH_CLASSES) {
    const t = r.truthByClass[c];
    const tpC = r.tpByClass[c];
    const fpC = r.fpByClass[c];
    const mC = r.missByClass[c];
    if (t === 0 && tpC === 0 && fpC === 0 && mC === 0) continue;
    lines.push(`| ${c} | ${t} | ${tpC} | ${fpC} | ${mC} |`);
  }
  lines.push('');
}

lines.push('## Known misses');
lines.push('');
lines.push('| app | class | file:line | why |');
lines.push('|---|---|---|---|');
if (knownMisses.length === 0) {
  lines.push('| — | — | — | no misses against the current (unreviewed) ground truth |');
} else {
  for (const m of knownMisses) {
    lines.push(`| ${m.app} | ${m.class} | \`${m.file}:${m.line}\` | ${m.why} |`);
  }
}
lines.push('');

const out = join(root, 'BENCHMARK.md');
writeFileSync(out, lines.join('\n'));
console.log(`wrote ${relative(root, out)}`);
console.log(
  JSON.stringify(
    results.map((r) => ({ id: r.id, sha: r.sha, tp: r.tp, fp: r.fp, miss: r.miss, ms: r.scan.ms })),
    null,
    2,
  ),
);
