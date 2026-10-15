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

const { BENCH_CLASSES, classForRule, precisionFromTriage, scoreFindings } = await import(
  pathToFileURL(scorePath).href
);

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
  {
    id: 'goof',
    repo: 'https://github.com/snyk-labs/nodejs-goof.git',
    sha: 'add14ba59e98240d9e00a235dd7d42cd61ae9912',
    holdout: true,
    seenHoldout: true,
  },
  {
    id: 'vulnerable-node',
    repo: 'https://github.com/cr0hn/vulnerable-node.git',
    sha: 'd68f2a3c9277ece2c2feb9976052033bdecd7fbe',
    holdout: true,
    seenHoldout: true,
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
    if (typeof e.inScope !== 'boolean') fail(`${path} entry missing inScope: ${JSON.stringify(e)}`);
    if (e.inScope === false && !e.reason) fail(`${path} out-of-scope entry needs reason`);
  }
  return truth;
}

function loadTriage(id) {
  const path = join(root, 'bench', id, 'triage.json');
  if (!existsSync(path)) return { reviewed: false, findings: [] };
  return JSON.parse(readFileSync(path, 'utf8'));
}

function autoVerdict(finding) {
  const file = (finding.file ?? '').replaceAll('\\', '/');
  const rule = finding.ruleId ?? '';
  if (rule.startsWith('DEPS-')) {
    return { verdict: 'realIssue', reason: 'OSV/lockfile advisory on an installed package' };
  }
  if (rule.startsWith('CONFIG-')) {
    return { verdict: 'realIssue', reason: 'config rule hit a real missing header/limit/CORS/rate-limit pattern' };
  }
  if (rule.startsWith('SECRET-') && /\.(html|md|yml|markdown)$/i.test(file)) {
    return { verdict: 'falsePositive', reason: 'secret-shaped text in documentation or challenge YAML' };
  }
  if (rule.startsWith('SECRET-') && /tutorial|fixture|example|challenge/i.test(file)) {
    return { verdict: 'falsePositive', reason: 'secret-shaped text in tutorial/example files' };
  }
  if (rule.startsWith('SAST-')) {
    return { verdict: 'unsure', reason: 'SAST hit did not match an in-scope ground-truth file/line' };
  }
  return { verdict: 'unsure', reason: 'no auto-triage rule for this finding' };
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
  const existing = loadTriage(app.id);
  const prev = new Map((existing.findings ?? []).map((t) => [`${t.ruleId}|${t.file}|${t.line}`, t]));
  const triageFindings = scored.unmatched.map((f) => {
    const file = (f.file ?? '').replaceAll('\\', '/');
    const line = f.line ?? 0;
    const key = `${f.ruleId}|${file}|${line}`;
    const kept = prev.get(key);
    if (kept?.verdict) {
      return {
        ruleId: f.ruleId,
        file,
        line,
        verdict: kept.verdict,
        reason: kept.reason,
      };
    }
    const auto = autoVerdict(f);
    return { ruleId: f.ruleId, file, line, ...auto };
  });
  const triagePath = join(root, 'bench', app.id, 'triage.json');
  writeFileSync(
    triagePath,
    `${JSON.stringify({ reviewed: false, findings: triageFindings }, null, 2)}\n`,
  );
  const prec = precisionFromTriage(triageFindings);
  const inScope = truth.entries.filter((e) => e.inScope);
  const tp = scored.truePositives.length;
  const miss = scored.inScopeMisses.length;
  const lineAttr = scored.lineAttributionOnly.length;
  results.push({
    id: app.id,
    sha: app.sha,
    repo: app.repo,
    holdout: app.holdout === true,
    seenHoldout: app.seenHoldout === true,
    reviewed: truth.reviewed === true,
    scan,
    scored,
    inScope: inScope.length,
    outOfScope: scored.outOfScope.length,
    tp,
    miss,
    lineAttr,
    unmatched: scored.unmatched.length,
    recall: pct(tp, tp + miss + lineAttr),
    precision: prec.precision,
    triage: prec,
    truthByClass: byClass(inScope),
    tpByClass: byClass(scored.truePositives),
    missByClass: byClass(scored.inScopeMisses),
    fpByClass: byClass(
      triageFindings
        .filter((t) => t.verdict === 'falsePositive')
        .map((t) => ({ class: classForRule(t.ruleId) })),
    ),
  });
}

const knownMisses = [];
for (const r of results) {
  for (const m of r.scored.inScopeMisses) {
    knownMisses.push({
      app: r.id,
      class: m.class,
      file: m.file,
      line: m.line,
      why: m.description,
    });
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
lines.push('- In-scope score: true positives / in-scope ground-truth entries (unreviewed).');
lines.push(
  '- Line attribution: a file-level (no-line) finding plus a later comment/line number on the same file is **not** counted as a recall gain.',
);
lines.push(
  '- Precision: self-triaged, unverified. `realIssue / (realIssue + falsePositive)` on unmatched findings listed in `bench/<app>/triage.json`. `unsure` is excluded from the denominator and counted separately per app.',
);
lines.push(
  '- Holdout apps are scored the same way. A seen holdout was used to find engine gaps or to re-score after an authorized rule change.',
);
lines.push('- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`');
lines.push('');

for (const r of results) {
  const holdoutLabel = r.seenHoldout ? ' (seen holdout)' : r.holdout ? ' (holdout)' : '';
  lines.push(`## ${r.id}${holdoutLabel}`);
  lines.push('');
  lines.push(`- Repo: ${r.repo}`);
  lines.push(`- Commit: \`${r.sha}\``);
  if (r.seenHoldout && r.id === 'goof') {
    lines.push('- Seen holdout: yes. Engine gaps were taken from this app; do not count this re-run as a recall gain.');
  } else if (r.seenHoldout) {
    lines.push('- Seen holdout: yes. Re-scored after an authorized rule change; do not count this as a recall gain.');
  } else if (r.holdout) {
    lines.push('- Holdout: yes. Untouched. Do not change rules based on this app.');
  }
  lines.push(`- Scan time: ${r.scan.ms} ms`);
  lines.push(`- Ground truth reviewed: ${r.reviewed}`);
  lines.push(`- Ground truth entries: ${r.inScope} in-scope / ${r.outOfScope} out-of-scope`);
  if (r.scan.error) lines.push(`- Scan error: ${r.scan.error}`);
  lines.push(`- Findings emitted: ${r.scan.findings.length}`);
  lines.push(`- In-scope true positives: ${r.tp}`);
  lines.push(`- In-scope misses: ${r.miss}`);
  if (r.lineAttr > 0) {
    const why = r.scored.lineAttributionOnly
      .map((e) => `${e.file}:${e.line} (${e.class})`)
      .join('; ');
    lines.push(
      `- Line-attribution only (not a recall gain): ${r.lineAttr} — ${why}`,
    );
  }
  lines.push(`- Unmatched findings (triaged): ${r.unmatched}`);
  lines.push(`- In-scope true positives / in-scope truth: ${r.tp}/${r.inScope}`);
  lines.push(
    `- Precision: self-triaged, unverified (${r.triage.realIssue} realIssue / ${r.triage.falsePositive} falsePositive; ${r.triage.unsure} unsure)`,
  );
  lines.push('');
  lines.push('| class | in-scope truth | TP | triaged FP | in-scope misses |');
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

lines.push('## Known misses (in-scope only)');
lines.push('');
lines.push('| app | class | file:line | why |');
lines.push('|---|---|---|---|');
if (knownMisses.length === 0) {
  lines.push('| — | — | — | no in-scope misses |');
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
    results.map((r) => ({
      id: r.id,
      inScope: r.inScope,
      outOfScope: r.outOfScope,
      tp: r.tp,
      miss: r.miss,
      lineAttr: r.lineAttr,
      holdout: r.holdout,
      precision: r.precision,
      unsure: r.triage.unsure,
      ms: r.scan.ms,
    })),
    null,
    2,
  ),
);
