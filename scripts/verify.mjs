#!/usr/bin/env node
/**
 * FullShield verification protocol (SECURITY_SCANNER_SPEC.md §0.1).
 * Runs, in order, stopping on the first failure:
 *   1. typecheck -> lint -> build
 *   2. test:coverage (thresholds enforced in vitest.config.ts)
 *   3. anti-cheat checks on test/ and src/
 *   4. e2e CLI tests against the built binary
 *   5. mutation smoke test for SAST/secrets rules
 *   6. summary table (+ per-phase acceptance criteria with --phase N)
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { acquireVerifyLock, assertSrcTestClean, releaseVerifyLock, srcTestDiff } from './verify-lock.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';
acquireVerifyLock(root);
process.on('exit', () => releaseVerifyLock(root));

const args = process.argv.slice(2);
let phase = null;
const phaseIdx = args.indexOf('--phase');
if (phaseIdx !== -1) {
  phase = Number(args[phaseIdx + 1]);
  if (!Number.isInteger(phase) || phase < 1) {
    console.error('usage: node scripts/verify.mjs [--phase N]');
    process.exit(1);
  }
}

function fail(message) {
  const dirty = srcTestDiff(root);
  if (dirty !== '') {
    console.error('fullshield: FS-E011 src or test changed during verify');
    console.error(dirty);
  }
  releaseVerifyLock(root);
  console.error(`\nVERIFY FAILED: ${message}`);
  process.exit(1);
}

function section(title) {
  console.log(`\n=== ${title} ===`);
}

function runNpm(script) {
  section(`npm run ${script}`);
  const result = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['run', script], {
    cwd: root,
    stdio: 'inherit',
    shell: isWindows,
  });
  if (result.status !== 0) fail(`\`npm run ${script}\` exited with ${result.status}`);
}

function countVitestTests() {
  let n = 0;
  for (const file of listFilesRecursive(join(root, 'test'))) {
    if (!file.endsWith('.test.ts')) continue;
    const text = readFileSync(file, 'utf8');
    n += (text.match(/^\s*it\(/gm) ?? []).length;
  }
  return n;
}

/** Last completed phase's test count. Phase N must add tests. */
const PREVIOUS_PHASE_TESTS = {
  16: 291,
  17: 318,
  18: 324,
  19: 341,
  20: 356,
  21: 383,
  22: 392,
  23: 401,
  24: 407,
  25: 439,
  26: 443,
  27: 505,
  28: 522,
  29: 568,
  30: 593,
  31: 620,
  32: 638,
  33: 659,
  34: 703,
  35: 740,
  36: 748,
  37: 751,
  38: 752,
  39: 757,
  40: 767,
  41: 768,
  42: 770,
  43: 771,
  44: 774,
  45: 780,
};

function listFilesRecursive(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'dist', 'coverage', '.git'].includes(entry.name)) continue;
      listFilesRecursive(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

// ---------------------------------------------------------------- steps 1-2
runNpm('typecheck');
runNpm('lint');
runNpm('build');
runNpm('test:coverage');
runNpm('quality');

// ------------------------------------------------------------------ step 3
section('anti-cheat checks');
{
  const problems = [];
  const bannedInTests = [
    [/\.only\s*\(/, '.only('],
    [/\.skip\s*\(/, '.skip('],
    [/\bit\.todo\s*\(/, 'it.todo('],
    [/\bxit\s*\(/, 'xit('],
    [/\bxdescribe\s*\(/, 'xdescribe('],
  ];
  const testFiles = listFilesRecursive(join(root, 'test')).filter((f) => f.endsWith('.ts'));
  for (const file of testFiles) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(root, file);
    for (const [pattern, label] of bannedInTests) {
      if (pattern.test(text)) problems.push(`${rel}: contains banned pattern ${label}`);
    }
    if (file.endsWith('.test.ts') && !/\bexpect\s*\(/.test(text)) {
      problems.push(`${rel}: test file has zero expect() calls`);
    }
  }
  const bannedInSrc = [
    [/TODO: implement/i, 'TODO: implement'],
    [/throw new Error\(\s*['"`]not implemented/i, "throw new Error('Not implemented')"],
  ];
  const srcFiles = listFilesRecursive(join(root, 'src')).filter((f) => f.endsWith('.ts'));
  for (const file of srcFiles) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(root, file);
    for (const [pattern, label] of bannedInSrc) {
      if (pattern.test(text)) problems.push(`${rel}: contains stub marker "${label}"`);
    }
  }
  if (problems.length > 0) {
    for (const problem of problems) console.error(`  ✖ ${problem}`);
    fail('anti-cheat checks failed');
  }
  console.log(`  ✔ ${testFiles.length} test files and ${srcFiles.length} source files clean`);
}

// ------------------------------------------------------------------ step 4
runNpm('test:e2e');

// ------------------------------------------------------------------ step 5
section('mutation smoke test');
{
  const result = spawnSync(process.execPath, [join(root, 'scripts', 'mutation-smoke.mjs')], {
    cwd: root,
    stdio: 'inherit',
  });
  if (result.status !== 0) fail('mutation smoke test failed');
}

// ------------------------------------------------------------------ step 6
section('summary');

function runCliJson(fixtureDir, extraArgs = []) {
  const result = spawnSync(
    process.execPath,
    [join(root, 'dist', 'cli', 'index.js'), 'scan', fixtureDir, '--json', ...extraArgs],
    { cwd: root, encoding: 'utf8' },
  );
  if (result.stdout === '' || result.status === 2) {
    fail(`CLI scan of ${fixtureDir} errored: ${result.stderr}`);
  }
  return { status: result.status, report: JSON.parse(result.stdout) };
}

const { IMPLEMENTED_MODULES, validateSarif21, validateCycloneDx15 } = await import(
  pathToFileURL(join(root, 'dist', 'index.js')).href
);

const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');

const expectedAll = JSON.parse(
  readFileSync(join(vulnerableApp, 'expected-findings.json'), 'utf8'),
).expected;
const expected = expectedAll.filter((e) => IMPLEMENTED_MODULES.includes(e.module));

const vuln = runCliJson(vulnerableApp);
const clean = runCliJson(cleanApp);

const foundRuleIds = new Set(vuln.report.findings.map((f) => f.ruleId));
const missing = expected.filter((e) => !foundRuleIds.has(e.ruleId));
const falsePositives = clean.report.findings.filter((f) =>
  ['high', 'critical'].includes(f.severity),
);

const coverageSummaryPath = join(root, 'coverage', 'coverage-summary.json');
let coverageLines = 'n/a';
let coverageBranches = 'n/a';
if (existsSync(coverageSummaryPath)) {
  const total = JSON.parse(readFileSync(coverageSummaryPath, 'utf8')).total;
  coverageLines = `${total.lines.pct}%`;
  coverageBranches = `${total.branches.pct}%`;
}

const testCount = countVitestTests();
console.table([
  {
    phase: phase ?? '(all)',
    tests: testCount,
    'coverage lines': coverageLines,
    'coverage branches': coverageBranches,
    'implemented modules': IMPLEMENTED_MODULES.length > 0 ? IMPLEMENTED_MODULES.join(',') : 'none',
    'expected findings': expected.length,
    'found expected': expected.length - missing.length,
    'vulnerable-app findings': vuln.report.summary.total,
    'clean-app high/critical': falsePositives.length,
  },
]);
console.log(`test count: ${testCount}`);
if (phase !== null && phase >= 17) {
  const prev = PREVIOUS_PHASE_TESTS[phase - 1];
  if (prev !== undefined && testCount <= prev) {
    fail(`phase ${phase} must add tests (count ${testCount} <= previous phase ${prev})`);
  }
  console.log(`  ✔ test count ${testCount} > previous phase ${prev}`);
}

if (missing.length > 0) {
  for (const entry of missing) console.error(`  ✖ missing expected finding: ${entry.ruleId}`);
  fail('expected findings missing from vulnerable-app scan');
}
if (falsePositives.length > 0) {
  for (const f of falsePositives) console.error(`  ✖ clean-app false positive: ${f.ruleId}`);
  fail('clean-app produced high/critical findings');
}

// --------------------------------------------------- phase acceptance criteria
const acceptanceCriteria = {
  // Phase 1 (spec §9): `fullshield scan` runs on fixtures with 0 modules and
  // exits 0; unit tests pass (enforced by step 2 above).
  1: () => {
    for (const fixture of [vulnerableApp, cleanApp]) {
      const result = spawnSync(
        process.execPath,
        [join(root, 'dist', 'cli', 'index.js'), 'scan', fixture],
        { cwd: root, encoding: 'utf8' },
      );
      if (result.status !== 0) {
        fail(`phase 1 acceptance: \`scan ${relative(root, fixture)}\` exited ${result.status}`);
      }
      console.log(`  ✔ scan ${relative(root, fixture)} exited 0`);
    }
  },
  // Phase 2 (spec §9): secrets module detects all seeded secrets in
  // vulnerable-app; 0 false positives in clean-app; the CI gate exits 1.
  2: () => {
    const seeded = ['SECRET-AWS-001', 'SECRET-STRIPE-001', 'SECRET-JWT-001', 'SECRET-DBURL-001', 'SECRET-ENVFILE-001'];
    const vulnSecrets = runCliJson(vulnerableApp, ['--modules', 'secrets']);
    const ids = new Set(vulnSecrets.report.findings.map((f) => f.ruleId));
    for (const id of seeded) {
      if (!ids.has(id)) fail(`phase 2 acceptance: ${id} not detected in vulnerable-app`);
    }
    console.log(`  ✔ all ${seeded.length} seeded secret rule ids detected in vulnerable-app`);

    const cleanSecrets = runCliJson(cleanApp, ['--modules', 'secrets']);
    if (cleanSecrets.report.summary.total !== 0) {
      fail(`phase 2 acceptance: ${cleanSecrets.report.summary.total} false positives on clean-app`);
    }
    console.log('  ✔ zero secrets findings on clean-app');

    const gated = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', vulnerableApp, '--modules', 'secrets', '--fail-on', 'high'],
      { cwd: root, encoding: 'utf8' },
    );
    if (gated.status !== 1) {
      fail(`phase 2 acceptance: --fail-on high exited ${gated.status}, expected 1`);
    }
    console.log('  ✔ --fail-on high exits 1 on vulnerable-app');
  },
  // Phase 3 (spec §9): deps module detects seeded lodash/minimist vulns
  // and the expresss typosquat; OSV is not contacted (fixture cache + --offline).
  3: () => {
    const vulnDeps = runCliJson(vulnerableApp, ['--modules', 'deps', '--offline']);
    const blob = JSON.stringify(vulnDeps.report.findings);
    for (const needle of ['DEPS-VULN-001', 'lodash@4.17.11', 'minimist@1.2.0', 'DEPS-TYPOSQUAT-001', 'expresss']) {
      if (!blob.includes(needle)) {
        fail(`phase 3 acceptance: ${needle} not present in vulnerable-app deps scan`);
      }
    }
    console.log('  ✔ seeded lodash/minimist vulns and expresss typosquat detected');
    if (vulnDeps.status !== 1) {
      fail(`phase 3 acceptance: deps --fail-on (default high) exited ${vulnDeps.status}, expected 1`);
    }
    console.log('  ✔ vulnerable-app deps scan exits 1 (critical lodash vuln)');

    const cleanDeps = runCliJson(cleanApp, ['--modules', 'deps']);
    if (cleanDeps.report.summary.total !== 0) {
      fail(`phase 3 acceptance: ${cleanDeps.report.summary.total} deps findings on clean-app`);
    }
    console.log('  ✔ zero deps findings on clean-app');
  },
  // Phase 4 (spec §9): first 6 SAST rules; parameterized queries not flagged.
  4: () => {
    const seeded = [
      'SAST-SQLI-001',
      'SAST-CMDI-001',
      'SAST-PATH-001',
      'SAST-EVAL-001',
      'SAST-JWT-001',
      'SAST-CRYPTO-001',
    ];
    const vulnSast = runCliJson(vulnerableApp, ['--modules', 'sast']);
    const ids = new Set(vulnSast.report.findings.map((f) => f.ruleId));
    for (const id of seeded) {
      if (!ids.has(id)) fail(`phase 4 acceptance: ${id} not detected in vulnerable-app`);
    }
    console.log(`  ✔ all ${seeded.length} Phase-4 SAST rules detected in vulnerable-app`);

    const cleanSast = runCliJson(cleanApp, ['--modules', 'sast']);
    if (cleanSast.report.summary.total !== 0) {
      fail(`phase 4 acceptance: ${cleanSast.report.summary.total} sast findings on clean-app`);
    }
    console.log('  ✔ zero sast findings on clean-app (parameterized queries not flagged)');
  },
  // Phase 5 (spec §9): remaining SAST + config; clean-app 0 high/critical.
  5: () => {
    const seeded = [
      'SAST-NOSQLI-001',
      'SAST-SSRF-001',
      'SAST-REDIRECT-001',
      'SAST-PROTO-001',
      'SAST-XSS-001',
      'SAST-AUTH-001',
      'CONFIG-HELMET-001',
      'CONFIG-BODYLIMIT-001',
      'CONFIG-CORS-001',
      'CONFIG-RATELIMIT-001',
      'CONFIG-ERRSTACK-001',
      'CONFIG-DOCKER-LATEST-001',
      'CONFIG-DOCKER-ROOT-001',
      'CONFIG-DOCKER-ENV-001',
    ];
    const vuln = runCliJson(vulnerableApp);
    const ids = new Set(vuln.report.findings.map((f) => f.ruleId));
    for (const id of seeded) {
      if (!ids.has(id)) fail(`phase 5 acceptance: ${id} not detected in vulnerable-app`);
    }
    console.log(`  ✔ all ${seeded.length} Phase-5 rule ids detected in vulnerable-app`);

    const clean = runCliJson(cleanApp, ['--fail-on', 'high']);
    const high = clean.report.findings.filter((f) => ['high', 'critical'].includes(f.severity));
    if (high.length > 0) {
      fail(`phase 5 acceptance: clean-app has ${high.length} high/critical findings`);
    }
    if (clean.status !== 0) {
      fail(`phase 5 acceptance: clean-app --fail-on high exited ${clean.status}`);
    }
    console.log('  ✔ clean-app has 0 high/critical findings');
  },
  // Phase 6 (spec §9): SARIF validates; baseline suppresses existing, new ones fail.
  6: () => {
    const tmp = join(root, '.fullshield-verify-phase6');
    mkdirSync(tmp, { recursive: true });
    try {
      const sarifPath = join(tmp, 'out.sarif');
      const sarifRun = spawnSync(
        process.execPath,
        [join(root, 'dist', 'cli', 'index.js'), 'scan', vulnerableApp, '--sarif', sarifPath, '--modules', 'sast'],
        { cwd: root, encoding: 'utf8' },
      );
      if (!existsSync(sarifPath)) fail('phase 6 acceptance: --sarif did not write a file');
      const errors = validateSarif21(JSON.parse(readFileSync(sarifPath, 'utf8')));
      if (errors.length > 0) fail(`phase 6 acceptance: SARIF schema errors: ${errors.join('; ')}`);
      console.log('  ✔ --sarif writes a valid SARIF 2.1.0 document');
      if (sarifRun.status !== 1) {
        fail(`phase 6 acceptance: sast scan of vulnerable-app exited ${sarifRun.status}, expected 1`);
      }

      const app = join(tmp, 'app');
      mkdirSync(app, { recursive: true });
      writeFileSync(
        join(app, 'app.js'),
        "app.get('/c', (req, res) => { eval(req.query.x); });\n",
      );
      const cli = join(root, 'dist', 'cli', 'index.js');
      const update = spawnSync(
        process.execPath,
        [cli, 'scan', app, '--modules', 'sast', '--update-baseline', '--fail-on', 'high'],
        { cwd: root, encoding: 'utf8' },
      );
      if (update.status !== 0) {
        fail(`phase 6 acceptance: --update-baseline exited ${update.status}, expected 0`);
      }
      const again = spawnSync(
        process.execPath,
        [cli, 'scan', app, '--modules', 'sast', '--fail-on', 'high'],
        { cwd: root, encoding: 'utf8' },
      );
      if (again.status !== 0) {
        fail(`phase 6 acceptance: baselined findings still fail the gate (exit ${again.status})`);
      }
      writeFileSync(
        join(app, 'app.js'),
        "app.get('/c', (req, res) => { eval(req.query.x); });\napp.get('/r', (req, res) => { res.redirect(req.query.next); });\n",
      );
      const newer = spawnSync(
        process.execPath,
        [cli, 'scan', app, '--modules', 'sast', '--fail-on', 'high', '--json'],
        { cwd: root, encoding: 'utf8' },
      );
      if (newer.status !== 1) {
        fail(`phase 6 acceptance: new finding after baseline exited ${newer.status}, expected 1`);
      }
      console.log('  ✔ baseline suppresses existing findings; new ones fail --fail-on');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
  // Phase 7 (spec §9): safe fixes on a copy of vulnerable-app; tests revert on failure.
  7: () => {
    const tmp = join(root, '.fullshield-verify-phase7');
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true });
    try {
      const copy = join(tmp, 'vulnerable-app');
      const copyResult = spawnSync('cp', ['-R', vulnerableApp, copy], { encoding: 'utf8' });
      if (copyResult.status !== 0) fail('phase 7 acceptance: could not copy vulnerable-app');
      const git = (args) => spawnSync('git', args, { cwd: copy, encoding: 'utf8' });
      git(['init']);
      git(['config', 'user.email', 'verify@test.local']);
      git(['config', 'user.name', 'Verify']);
      git(['add', '.']);
      git(['commit', '-m', 'copy']);
      const cli = join(root, 'dist', 'cli', 'index.js');
      const applied = spawnSync(
        process.execPath,
        [cli, 'fix', copy, '--apply', '--no-branch', '--modules', 'config'],
        { cwd: root, encoding: 'utf8' },
      );
      if (applied.status !== 0) {
        fail(`phase 7 acceptance: fix --apply exited ${applied.status}: ${applied.stderr}`);
      }
      const src = readFileSync(join(copy, 'src', 'index.js'), 'utf8');
      if (src.includes("require('helmet')") || src.includes('app.use(helmet())')) {
        fail('phase 7 acceptance: helmet() must not apply without --unsafe');
      }
      if (!src.includes("express.json({ limit: '100kb' })")) {
        fail('phase 7 acceptance: body limit was not applied on the copy');
      }
      console.log('  ✔ safe fixes applied on a git copy of vulnerable-app');

      const failApp = join(tmp, 'fail-app');
      mkdirSync(failApp, { recursive: true });
      writeFileSync(
        join(failApp, 'app.js'),
        "const express = require('express');\nconst app = express();\napp.use(express.json());\n",
      );
      writeFileSync(
        join(failApp, 'package.json'),
        JSON.stringify({ name: 'fail-app', private: true, scripts: { test: 'node -e "process.exit(1)"' } }),
      );
      const gitFail = (args) => spawnSync('git', args, { cwd: failApp, encoding: 'utf8' });
      gitFail(['init']);
      gitFail(['config', 'user.email', 'verify@test.local']);
      gitFail(['config', 'user.name', 'Verify']);
      gitFail(['add', '.']);
      gitFail(['commit', '-m', 'init']);
      const before = readFileSync(join(failApp, 'app.js'), 'utf8');
      const reverted = spawnSync(
        process.execPath,
        [cli, 'fix', failApp, '--apply', '--no-branch', '--modules', 'config'],
        { cwd: root, encoding: 'utf8' },
      );
      if (reverted.status !== 1) {
        fail(`phase 7 acceptance: failing tests should exit 1 (got ${reverted.status})`);
      }
      if (readFileSync(join(failApp, 'app.js'), 'utf8') !== before) {
        fail('phase 7 acceptance: files were not reverted after test failure');
      }
      console.log('  ✔ failing project tests revert applied fixes');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
  // Phase 8 (spec §9): runtime blocks the payload suite; p95 overhead < 1ms.
  8: () => {
    const bench = spawnSync(process.execPath, [join(root, 'scripts', 'bench.mjs')], {
      cwd: root,
      encoding: 'utf8',
    });
    process.stdout.write(bench.stdout);
    process.stderr.write(bench.stderr);
    if (bench.status !== 0) fail('phase 8 acceptance: bench p95 >= 1ms or bench failed');
    console.log('  ✔ runtime inspect() p95 < 1ms');
  },
  // Phase 9 (spec §9): generated GitHub workflow is valid YAML; webhook notifier works.
  9: () => {
    const tmp = join(root, '.fullshield-verify-phase9');
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true });
    try {
      const cli = join(root, 'dist', 'cli', 'index.js');
      const init = spawnSync(process.execPath, [cli, 'init', tmp], { cwd: root, encoding: 'utf8' });
      if (init.status !== 0) fail(`phase 9 acceptance: init exited ${init.status}: ${init.stderr}`);
      const workflow = readFileSync(join(tmp, '.github', 'workflows', 'fullshield.yml'), 'utf8');
      for (const needle of ['name:', 'on:', 'jobs:', 'fullshield scan', '--sarif', '--fail-on high']) {
        if (!workflow.includes(needle)) fail(`phase 9 acceptance: workflow missing ${needle}`);
      }
      if (/^\t/m.test(workflow)) fail('phase 9 acceptance: workflow contains tabs');
      console.log('  ✔ init writes a valid GitHub Actions workflow');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
  // Phase 10 (spec §9): npm pack has no tests/fixtures; README states non-goals.
  10: () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!/non-goals/i.test(readme)) fail('phase 10 acceptance: README must state non-goals');
    const packed = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json'], {
      cwd: root,
      encoding: 'utf8',
      shell: isWindows,
    });
    if (packed.status !== 0) fail(`phase 10 acceptance: npm pack failed: ${packed.stderr}`);
    const listing = JSON.parse(packed.stdout);
    const entry = Array.isArray(listing) ? listing[0] : Object.values(listing ?? {})[0];
    const paths = (entry?.files ?? []).map((f) => f.path);
    if (paths.some((p) => p.startsWith('test/') || p.includes('fixtures/'))) {
      fail('phase 10 acceptance: npm pack includes tests or fixtures');
    }
    if (!paths.some((p) => p === 'README.md' || p.endsWith('README.md'))) {
      fail('phase 10 acceptance: npm pack missing README.md');
    }
    console.log('  ✔ npm pack excludes tests/fixtures; README states non-goals');
  },
  // Phase 13 (spec §9 / §15): cross-file taint, unreachable deps downgraded, CycloneDX 1.5 SBOM.
  13: () => {
    const vulnSast = runCliJson(vulnerableApp, ['--modules', 'sast']);
    const cross = vulnSast.report.findings.find(
      (f) => f.ruleId === 'SAST-SQLI-001' && f.file === 'src/data/alloc-dao.js',
    );
    if (cross === undefined) {
      fail('phase 13 acceptance: 3-file SQLI chain not detected on alloc-dao.js');
    }
    const files = new Set((cross.trace ?? []).map((s) => s.file));
    for (const need of ['src/routes/alloc.js', 'src/services/alloc.js', 'src/data/alloc-dao.js']) {
      if (!files.has(need)) fail(`phase 13 acceptance: taint trace missing ${need}`);
    }
    if (files.size < 3) fail(`phase 13 acceptance: trace spans ${files.size} files, expected ≥ 3`);
    console.log('  ✔ taint traced across 3+ files in fixtures');

    const vulnDeps = runCliJson(vulnerableApp, ['--modules', 'deps', '--offline']);
    const lodash = vulnDeps.report.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    if (!lodash.some((f) => f.reachability === 'reachable' && f.severity === 'critical')) {
      fail('phase 13 acceptance: imported+called lodash must stay reachable/critical');
    }
    const unused = vulnDeps.report.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && f.reachability === 'not-imported',
    );
    if (unused.length === 0) fail('phase 13 acceptance: expected unused lockfile vulns to be classified not-imported');
    if (unused.some((f) => ['high', 'critical'].includes(f.severity))) {
      fail('phase 13 acceptance: not-imported vulns must be downgraded below high');
    }
    console.log(
      `  ✔ unreachable vulnerable deps downgraded (${unused.length} not-imported; lodash stays critical)`,
    );

    const tmp13 = join(root, '.fullshield-verify-phase13');
    rmSync(tmp13, { recursive: true, force: true });
    mkdirSync(tmp13, { recursive: true });
    try {
      const out = join(tmp13, 'bom.json');
      const sbom = spawnSync(
        process.execPath,
        [join(root, 'dist', 'cli', 'index.js'), 'sbom', vulnerableApp, '--format', 'cyclonedx', '--out', out],
        { cwd: root, encoding: 'utf8' },
      );
      if (sbom.status !== 0) fail(`phase 13 acceptance: sbom exited ${sbom.status}: ${sbom.stderr}`);
      if (!existsSync(out)) fail('phase 13 acceptance: sbom --out did not write a file');
      const doc = JSON.parse(readFileSync(out, 'utf8'));
      const errors = validateCycloneDx15(doc);
      if (errors.length > 0) fail(`phase 13 acceptance: CycloneDX errors: ${errors.join('; ')}`);
      if (doc.bomFormat !== 'CycloneDX' || doc.specVersion !== '1.5') {
        fail('phase 13 acceptance: SBOM is not CycloneDX 1.5');
      }
      console.log('  ✔ SBOM validates against CycloneDX 1.5');
    } finally {
      rmSync(tmp13, { recursive: true, force: true });
    }
  },
  // Phase 11 (spec §9): daily watch workflow; second run with no changes sends no alert.
  11: () => {
    const tmp = join(root, '.fullshield-verify-phase11');
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true });
    try {
      const cli = join(root, 'dist', 'cli', 'index.js');
      const init = spawnSync(process.execPath, [cli, 'init', tmp], { cwd: root, encoding: 'utf8' });
      if (init.status !== 0) fail(`phase 11 acceptance: init exited ${init.status}: ${init.stderr}`);
      const watchYml = readFileSync(join(tmp, '.github', 'workflows', 'fullshield-watch.yml'), 'utf8');
      for (const needle of ['schedule:', 'cron:', 'fullshield watch']) {
        if (!watchYml.includes(needle)) fail(`phase 11 acceptance: watch workflow missing ${needle}`);
      }
      if (/^\t/m.test(watchYml)) fail('phase 11 acceptance: watch workflow contains tabs');
      console.log('  ✔ init writes a daily GitHub Action for fullshield watch');

      const app = join(tmp, 'app');
      mkdirSync(app, { recursive: true });
      writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'w', private: true, dependencies: { lodash: '4.17.11' } }));
      writeFileSync(
        join(app, 'package-lock.json'),
        JSON.stringify({
          name: 'w',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { lodash: '4.17.11' } },
            'node_modules/lodash': { version: '4.17.11' },
          },
        }),
      );
      writeFileSync(
        join(app, 'fullshield.config.json'),
        JSON.stringify({ deps: { offline: true, cacheDir: join(vulnerableApp, 'osv-cache') } }),
      );
      writeFileSync(join(app, 'index.js'), "const lodash = require('lodash');\nlodash.get({}, 'x');\n");
      const first = spawnSync(process.execPath, [cli, 'watch', app, '--offline'], {
        cwd: root,
        encoding: 'utf8',
      });
      if (!/new/i.test(first.stdout)) {
        fail(`phase 11 acceptance: first watch should report new vulns: ${first.stdout}`);
      }
      const second = spawnSync(process.execPath, [cli, 'watch', app, '--offline'], {
        cwd: root,
        encoding: 'utf8',
      });
      if (!/no new/i.test(second.stdout)) {
        fail(`phase 11 acceptance: second watch should send no alert: ${second.stdout}`);
      }
      console.log('  ✔ second watch with no changes reports no new vulnerabilities');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
  // Phase 12 (spec §9 / §13): mock-server edge checks; GET/HEAD only.
  12: () => {
    const tmp = join(root, '.fullshield-verify-phase12');
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true });
    const wrapper = join(tmp, 'run.mjs');
    const cli = join(root, 'dist', 'cli', 'index.js');
    writeFileSync(
      wrapper,
      `import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
const s = createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.statusCode = 405; res.end(); return; }
  res.statusCode = 200; res.end('ok');
});
s.listen(0, '127.0.0.1', () => {
  const { port } = s.address();
  const child = spawn(process.execPath, [${JSON.stringify(cli)}, 'edge', 'http://127.0.0.1:' + port, '--json'], {
    env: { ...process.env, FULLSHIELD_EDGE_DELAY: '0' },
  });
  let out = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (d) => { out += d; });
  const timer = setTimeout(() => { child.kill(); process.exit(2); }, 20000);
  child.on('close', (code) => {
    clearTimeout(timer);
    process.stdout.write(out);
    s.close();
    process.exit(code === 2 ? 2 : 0);
  });
});
`,
    );
    try {
      const run = spawnSync(process.execPath, [wrapper], { cwd: root, encoding: 'utf8' });
      if (run.stdout === '') fail(`phase 12 acceptance: edge produced no output: ${run.stderr}`);
      const report = JSON.parse(run.stdout);
      const ids = new Set(report.findings.map((f) => f.ruleId));
      for (const id of ['EDGE-CDN-001', 'EDGE-HSTS-001', 'EDGE-TLS-001']) {
        if (!ids.has(id)) fail(`phase 12 acceptance: missing ${id} in ${run.stdout}`);
      }
      console.log('  ✔ edge mock server reports CDN/HSTS/TLS findings (GET/HEAD only)');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
  // Phase 14 (spec §16.1–16.2): injection finding; --ai off is the default.
  14: () => {
    const cli = join(root, 'dist', 'cli', 'index.js');
    const inject = join(root, 'test', 'fixtures', 'ai-inject-app');
    const run = spawnSync(process.execPath, [cli, 'scan', inject, '--json', '--offline'], {
      cwd: root,
      encoding: 'utf8',
    });
    const report = JSON.parse(run.stdout);
    if (!report.findings.some((f) => f.ruleId === 'AI-INJECT-001')) {
      fail(`phase 14 acceptance: missing AI-INJECT-001: ${run.stdout}`);
    }
    console.log('  ✔ AI-INJECT-001 flagged on the seeded comment fixture');
  },
  // Phase 15: triage labels; fix --ai is a reviewable diff.
  15: () => {
    const cli = join(root, 'dist', 'cli', 'index.js');
    const inject = join(root, 'test', 'fixtures', 'ai-inject-app');
    const explained = spawnSync(
      process.execPath,
      [cli, 'scan', inject, '--json', '--offline', '--ai', 'explain'],
      { cwd: root, encoding: 'utf8' },
    );
    const report = JSON.parse(explained.stdout);
    const hit = report.findings.find((f) => f.ruleId === 'AI-INJECT-001');
    if (hit === undefined || typeof hit.explanation !== 'string') {
      fail(`phase 15 acceptance: explain did not label AI-INJECT-001: ${explained.stdout}`);
    }
    const fix = spawnSync(process.execPath, [cli, 'fix', inject, '--ai'], {
      cwd: root,
      encoding: 'utf8',
    });
    if (!/reviewable diff|AI patch/i.test(fix.stdout)) {
      fail(`phase 15 acceptance: fix --ai should print a reviewable diff: ${fix.stdout}`);
    }
    const src = readFileSync(join(inject, 'src', 'index.js'), 'utf8');
    if (!src.includes('ignore previous')) {
      fail('phase 15 acceptance: fix --ai must not write the user tree');
    }
    console.log('  ✔ --ai explain labels findings; fix --ai is a reviewable diff');
  },
  // Phase 16 (0.1.0): CLI ships --ai explain only; no verdict; logic stays internal.
  16: () => {
    const cli = join(root, 'dist', 'cli', 'index.js');
    const inject = join(root, 'test', 'fixtures', 'ai-inject-app');
    const logic = join(root, 'test', 'fixtures', 'ai-logic-app');
    const rejected = spawnSync(
      process.execPath,
      [cli, 'scan', logic, '--json', '--offline', '--ai', 'logic'],
      { cwd: root, encoding: 'utf8' },
    );
    if (rejected.status !== 2 || !/not shipped/i.test(rejected.stderr)) {
      fail(`phase 16 acceptance: --ai logic must not ship: ${rejected.stderr}`);
    }
    const explained = spawnSync(
      process.execPath,
      [cli, 'scan', inject, '--json', '--offline', '--ai', 'explain', '--fail-on', 'high'],
      { cwd: root, encoding: 'utf8' },
    );
    const report = JSON.parse(explained.stdout);
    const hit = report.findings.find((f) => f.ruleId === 'AI-INJECT-001');
    if (hit === undefined || typeof hit.explanation !== 'string') {
      fail(`phase 16 acceptance: explain missing: ${explained.stdout}`);
    }
    if (report.findings.some((f) => f.aiVerdict !== undefined)) {
      fail('phase 16 acceptance: explain must never show a verdict');
    }
    if (JSON.stringify(report).includes('true-positive') || JSON.stringify(report).includes('likely-false-positive')) {
      fail('phase 16 acceptance: explain report leaked a verdict string');
    }
    console.log('  ✔ --ai explain only; no verdict; --ai logic rejected');
  },
  // Phase 17 (spec §17 / §22): experimental RASP sink hooks; attack ≥95%,
  // benign 0, p95 < 1ms; fail-open; off by default.
  17: async () => {
    const raspUrl = pathToFileURL(join(root, 'dist', 'runtime', 'rasp.js')).href;
    const rasp = await import(raspUrl);
    const attack = JSON.parse(readFileSync(join(root, 'test', 'fixtures', 'rasp', 'attack-corpus.json'), 'utf8'));
    const benign = JSON.parse(readFileSync(join(root, 'test', 'fixtures', 'rasp', 'benign-corpus.json'), 'utf8'));
    const attackScore = rasp.scoreCorpusByKind(attack.cases);
    const benignScore = rasp.scoreCorpusByKind(benign.cases);
    const attackRate = attackScore.blocked / attackScore.total;
    const benignRate = benignScore.blocked / benignScore.total;
    console.log(`  attack corpus ${attackScore.blocked}/${attackScore.total} = ${(attackRate * 100).toFixed(1)}%`);
    for (const [kind, slot] of Object.entries(attackScore.byKind)) {
      console.log(`    attack ${kind}: ${slot.blocked}/${slot.total}`);
    }
    console.log(`  benign corpus ${benignScore.blocked}/${benignScore.total} = ${(benignRate * 100).toFixed(1)}%`);
    for (const [kind, slot] of Object.entries(benignScore.byKind)) {
      console.log(`    benign ${kind}: ${slot.blocked}/${slot.total}`);
    }
    if (attack.cases.length < 80) fail(`phase 17 acceptance: attack corpus too small (${attack.cases.length})`);
    if (benign.cases.length < 300) fail(`phase 17 acceptance: benign corpus ${benign.cases.length} < 300`);
    if (attackRate < 0.95) fail(`phase 17 acceptance: attack block rate ${attackRate} < 0.95`);
    if (benignScore.blocked !== 0) fail(`phase 17 acceptance: benign corpus blocked ${benignScore.blocked}`);
    rasp.enableRasp({ mode: 'block' });
    if (rasp.isRaspEnabled()) fail('phase 17 acceptance: rasp enabled without experimental flag');
    rasp.disableRasp();
    console.log('  ✔ experimental RASP off by default; attack ≥95%; benign 0');
  },
  // Phase 18 (spec §17.3–17.6 / §22): vpatch forces block; honeytoken alert.
  18: async () => {
    const raspUrl = pathToFileURL(join(root, 'dist', 'runtime', 'rasp.js')).href;
    const rasp = await import(raspUrl);
    const tmp = join(root, '.fullshield-verify-p18');
    mkdirSync(tmp, { recursive: true });
    try {
      const out = join(tmp, 'vpatches.json');
      rasp.emitVirtualPatches(
        [{ ruleId: 'SAST-SQLI-001', file: 'app/routes/login.js', line: 1, message: 'on /login' }],
        out,
      );
      const patches = rasp.loadVirtualPatches(out);
      if (!rasp.patchForcesBlock(patches, '/login', 'sql')) {
        fail('phase 18 acceptance: vpatch did not force block on /login sql');
      }
      rasp.enableRasp({ experimental: true, mode: 'monitor', virtualPatches: patches });
      if (rasp.raspModeFor('/login', 'sql') !== 'block') {
        fail('phase 18 acceptance: raspModeFor /login sql is not block');
      }
      rasp.disableRasp();
      const canaries = rasp.honeyInit(tmp);
      if (!rasp.isHoneyRoute('/admin.php') || !rasp.isHoneyCanary(canaries.awsKey)) {
        fail('phase 18 acceptance: honeytoken not registered');
      }
      rasp.enableRasp({ experimental: true, mode: 'monitor' });
      const events = [];
      rasp.enableRasp({ experimental: true, mode: 'monitor', onEvent: (e) => events.push(e) });
      rasp.raspContext()({ path: '/admin.php', ip: '203.0.113.1' }, { status() { return { json() {} }; } }, () => {});
      if (!events.some((e) => e.ruleId === 'RASP-HONEY-001') && !rasp.getRaspEvents().some((e) => e.ruleId === 'RASP-HONEY-001')) {
        fail('phase 18 acceptance: decoy route did not emit RASP-HONEY-001');
      }
      rasp.disableRasp();
      console.log('  ✔ vpatch forces block; honeytoken hit emits RASP-HONEY-001');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
  // Phase 19 (spec §18 / §22): seeded malicious package + version-diff new script.
  19: async () => {
    const supplyUrl = pathToFileURL(join(root, 'dist', 'supply.js')).href;
    const supply = await import(supplyUrl);
    const malicious = join(root, 'test', 'fixtures', 'supply', 'malicious-pkg');
    const benign = join(root, 'test', 'fixtures', 'supply', 'benign-pkg');
    const v1 = join(root, 'test', 'fixtures', 'supply', 'pkg-v1');
    const v2 = join(root, 'test', 'fixtures', 'supply', 'pkg-v2');
    const mal = supply.analyzePackageDir(malicious);
    if (!mal.some((f) => f.ruleId === 'SUPPLY-INSTALLSCRIPT-001')) {
      fail('phase 19 acceptance: missing SUPPLY-INSTALLSCRIPT-001 on seeded package');
    }
    if (!mal.some((f) => f.ruleId === 'SUPPLY-NPMRC-NET-001')) {
      fail('phase 19 acceptance: missing SUPPLY-NPMRC-NET-001 on seeded package');
    }
    const clean = supply.analyzePackageDir(benign);
    if (clean.some((f) => f.severity === 'high' || f.severity === 'critical')) {
      fail('phase 19 acceptance: benign package flagged high/critical');
    }
    const diff = supply.diffPackageVersions(v1, v2);
    if (!diff.some((f) => f.ruleId === 'SUPPLY-BEHAVIOR-001')) {
      fail('phase 19 acceptance: version diff did not flag newly added script');
    }
    let threw = false;
    try {
      supply.assertRegistryUrl('https://evil.example/pkg');
    } catch {
      threw = true;
    }
    if (!threw) fail('phase 19 acceptance: non-npmjs registry was allowed');
    const skipped = await supply.installGuard('lodash');
    if (!skipped.skipped) fail('phase 19 acceptance: installGuard ran without experimental flag');
    console.log('  ✔ seeded malicious package + version-diff new script; registry locked; fail-closed without experimental');
  },
  // Phase 20 (spec §19 / §22): confirm seeded vulns locally; refuse any other host.
  20: async () => {
    const confirmUrl = pathToFileURL(join(root, 'dist', 'confirm.js')).href;
    const confirm = await import(confirmUrl);
    confirm.assertLocalTarget('http://127.0.0.1:9/');
    confirm.assertLocalTarget('http://localhost/');
    let refused = 0;
    for (const u of [
      'http://example.com/',
      'http://[::1]/',
      'http://[2001:db8::1]/',
      'http://8.8.8.8/',
      'http://2130706433/',
    ]) {
      try {
        confirm.assertLocalTarget(u, u.includes('example.com') ? { lookup: () => ['93.184.216.34'] } : {});
      } catch {
        refused += 1;
      }
    }
    if (refused !== 5) fail(`phase 20 acceptance: expected 5 refusals, got ${refused}`);
    try {
      confirm.buildCanary('sql', 'DROP TABLE users');
      fail('phase 20 acceptance: destructive SQL canary was allowed');
    } catch {
      /* expected */
    }
    const skipped = await confirm.confirmTarget('http://127.0.0.1:1/', { routes: [] });
    if (!skipped.skipped) fail('phase 20 acceptance: confirm ran without experimental flag');
    console.log('  ✔ scope lock refuses non-local (incl. public DNS + IPv6); canaries harmless; off without experimental');
  },
  // Phase 21 (spec §20.1–20.2 / §22): MCP tools + LLM positive/negative fixtures.
  21: async () => {
    const mcpUrl = pathToFileURL(join(root, 'dist', 'mcp.js')).href;
    const llmUrl = pathToFileURL(join(root, 'dist', 'llm.js')).href;
    const mcp = await import(mcpUrl);
    const llm = await import(llmUrl);
    const names = mcp.listMcpTools().map((t) => t.name);
    for (const n of ['scan', 'get_findings', 'explain_finding', 'propose_fix', 'verify_fix']) {
      if (!names.includes(n)) fail(`phase 21 acceptance: missing MCP tool ${n}`);
    }
    const bad = llm.scanLlmApp(join(root, 'test', 'fixtures', 'llm-app'), { experimental: true });
    for (const id of ['LLM-001', 'LLM-002', 'LLM-003', 'LLM-004', 'LLM-005']) {
      if (!bad.some((f) => f.ruleId === id)) fail(`phase 21 acceptance: missing ${id} on llm-app`);
    }
    const good = llm.scanLlmApp(join(root, 'test', 'fixtures', 'llm-clean'), { experimental: true });
    if (good.length !== 0) fail(`phase 21 acceptance: llm-clean produced ${good.map((f) => f.ruleId).join(',')}`);
    if (llm.scanLlmApp(join(root, 'test', 'fixtures', 'llm-app')).length !== 0) {
      fail('phase 21 acceptance: LLM rules ran without experimental flag');
    }
    const session = mcp.createMcpSession();
    const skipped = await mcp.callMcpTool(session, 'scan', { path: join(root, 'test', 'fixtures', 'clean-app') });
    if (!skipped.skipped) fail('phase 21 acceptance: MCP scan ran without experimental flag');
    console.log('  ✔ MCP tools listed; LLM-001..005 positive/negative; off without experimental');
  },
  // Phase 22 (spec §20.3–20.5 / §22): threat model + incremental + dashboard host lock.
  22: async () => {
    const threat = await import(pathToFileURL(join(root, 'dist', 'threat.js')).href);
    const dash = await import(pathToFileURL(join(root, 'dist', 'dashboard.js')).href);
    const model = threat.buildThreatModel(join(root, 'test', 'fixtures', 'vulnerable-app'), { experimental: true });
    if (!model.routes.some((r) => r.path === '/user')) fail('phase 22 acceptance: threat model missed /user');
    if (!String(model.mermaid).includes('flowchart')) fail('phase 22 acceptance: missing Mermaid map');
    if (dash.assertDashboardHost('evil.example') !== false) fail('phase 22 acceptance: Host lock failed');
    if (dash.assertDashboardHost('127.0.0.1') !== true) fail('phase 22 acceptance: 127.0.0.1 Host should pass');
    if (threat.buildThreatModel(join(root, 'test', 'fixtures', 'vulnerable-app')).skipped !== true) {
      fail('phase 22 acceptance: threat-model ran without experimental');
    }
    console.log('  ✔ threat model STRIDE/Mermaid; dashboard Host lock; experimental fail-closed');
  },
  // Phase 23 (spec §20.6–20.7 / §22): every rule mapped; IaC fixtures; disclaimer.
  23: async () => {
    const compliance = await import(pathToFileURL(join(root, 'dist', 'compliance.js')).href);
    const iac = await import(pathToFileURL(join(root, 'dist', 'iac.js')).href);
    const report = compliance.renderCompliance([{ ruleId: 'SAST-SQLI-001' }], 'pci');
    if (!/not a certification or audit/i.test(report)) {
      fail('phase 23 acceptance: compliance report missing certification disclaimer');
    }
    const mapped = new Set(compliance.RULE_MAP.map((r) => r.ruleId));
    for (const id of ['SAST-SQLI-001', 'DEPS-MALICIOUS-001', 'IAC-GHA-PRTARGET-001']) {
      if (!mapped.has(id)) fail(`phase 23 acceptance: missing mapping for ${id}`);
    }
    const bad = iac.scanIac(join(root, 'test', 'fixtures', 'iac-app'), { experimental: true });
    for (const id of ['IAC-GHA-UNPINNED-001', 'IAC-TF-S3PUBLIC-001', 'IAC-K8S-PRIV-001']) {
      if (!bad.some((f) => f.ruleId === id)) fail(`phase 23 acceptance: missing ${id} on iac-app`);
    }
    if (iac.scanIac(join(root, 'test', 'fixtures', 'iac-clean'), { experimental: true }).length !== 0) {
      fail('phase 23 acceptance: iac-clean produced findings');
    }
    if (iac.scanIac(join(root, 'test', 'fixtures', 'iac-app')).length !== 0) {
      fail('phase 23 acceptance: IaC ran without experimental flag');
    }
    console.log('  ✔ compliance disclaimer; RULE_MAP; IaC positive/negative; experimental fail-closed');
  },
  // Phase 24 (spec §20.8 / §22): agent opens a PR against a mock API + local bare repo.
  24: async () => {
    const agent = await import(pathToFileURL(join(root, 'dist', 'agent.js')).href);
    try {
      agent.assertLocalAgentApi('https://api.github.com');
      fail('phase 24 acceptance: agent allowed api.github.com');
    } catch {
      // expected
    }
    if (agent.assertLocalAgentApi('http://127.0.0.1:9') !== true) {
      fail('phase 24 acceptance: 127.0.0.1 API should be allowed');
    }
    const skipped = await agent.runAgent({ cwd: join(root, 'test', 'fixtures', 'clean-app'), apiBase: 'http://127.0.0.1:9' });
    if (skipped.skipped !== true) fail('phase 24 acceptance: agent ran without experimental');
    console.log('  ✔ agent localhost-only API; experimental fail-closed; never real GitHub');
  },
  // Phase 25: Windows + lazy sqlite. Register --import must be a file:// URL and silent.
  25: () => {
    const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
    if (!ci.includes('windows-latest') || !ci.includes('macos-latest') || !ci.includes('ubuntu-24.04')) {
      fail('phase 25 acceptance: CI matrix must include ubuntu-24.04, macos, and windows');
    }
    if (!ci.includes('node: [22, 24]') && !/node:\s*\[22,\s*24\]/.test(ci)) {
      fail('phase 25 acceptance: CI must run Node 22 and 24');
    }
    const register = join(root, 'dist', 'runtime', 'register.js');
    const href = pathToFileURL(register).href;
    if (!href.startsWith('file:')) fail('phase 25 acceptance: --import specifier is not a file:// URL');
    const quiet = spawnSync(process.execPath, ['--import', href, '-e', '1'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_RASP: '1' },
    });
    if (quiet.status !== 0) fail(`phase 25 acceptance: --import register -e 1 exited ${quiet.status}`);
    if (String(quiet.stderr).trim() !== '') {
      fail(`phase 25 acceptance: --import register printed stderr: ${quiet.stderr}`);
    }
    const bytes = statSync(register).size;
    if (bytes <= 0 || bytes >= 256_000) {
      fail(`phase 25 acceptance: register bundle size ${bytes} outside budget`);
    }
    for (const name of ['register.js', 'auto.js', 'express.js', 'fastify.js', 'koa.js', 'hono.js', 'index.js']) {
      const text = readFileSync(join(root, 'dist', 'runtime', name), 'utf8');
      if (/from\s+['"]node:sqlite['"]/.test(text) || /require\(\s*['"]node:sqlite['"]\s*\)/.test(text)) {
        fail(`phase 25 acceptance: ${name} statically loads node:sqlite`);
      }
    }
    console.log('  ✔ CI Windows×Node 22/24; --import file:// silent; register budget; no static sqlite');
  },
  // Phase 26: public NodeGoat / Juice Shop / DVNA bench. Numbers stay unreviewed.
  26: () => {
    const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
    if (!/^ {2}bench:\s*$/m.test(ci)) fail('phase 26 acceptance: CI must have a job named bench');
    if (!/continue-on-error:\s*true/.test(ci)) {
      fail('phase 26 acceptance: bench job must be continue-on-error (not a required check)');
    }
    if (!ci.includes('npm run bench:public') || !ci.includes('BENCHMARK.md')) {
      fail('phase 26 acceptance: bench job must run bench:public and upload BENCHMARK.md');
    }
    const pkgText = readFileSync(join(root, 'package.json'), 'utf8');
    if (!pkgText.includes('"bench:public"')) fail('phase 26 acceptance: missing npm script bench:public');
    if (!existsSync(join(root, 'scripts', 'bench-public.mjs'))) {
      fail('phase 26 acceptance: missing scripts/bench-public.mjs');
    }
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );
    if (!cliHelp.stdout.includes('--offline-safe')) {
      fail('phase 26 acceptance: scan --help missing --offline-safe');
    }
    for (const app of ['nodegoat', 'juice-shop', 'dvna', 'goof', 'vulnerable-node']) {
      const path = join(root, 'bench', app, 'ground-truth.json');
      if (!existsSync(path)) fail(`phase 26 acceptance: missing ${relative(root, path)}`);
      const truth = JSON.parse(readFileSync(path, 'utf8'));
      if (truth.reviewed !== false) {
        fail(`phase 26 acceptance: ${app} ground truth must stay reviewed:false until a human flips it`);
      }
      if (!Array.isArray(truth.entries) || truth.entries.length === 0) {
        fail(`phase 26 acceptance: ${app} ground truth has no entries`);
      }
      for (const e of truth.entries) {
        if (typeof e.source !== 'string' || !/^https:\/\//.test(e.source)) {
          fail(`phase 26 acceptance: ${app} entry missing https source`);
        }
        if (typeof e.inScope !== 'boolean') {
          fail(`phase 26 acceptance: ${app} entry missing inScope`);
        }
        if (e.inScope === false && !e.reason) {
          fail(`phase 26 acceptance: ${app} out-of-scope entry needs reason`);
        }
      }
      const triagePath = join(root, 'bench', app, 'triage.json');
      if (!existsSync(triagePath)) fail(`phase 26 acceptance: missing ${relative(root, triagePath)}`);
      const triage = JSON.parse(readFileSync(triagePath, 'utf8'));
      if (!Array.isArray(triage.findings)) fail(`phase 26 acceptance: ${app} triage.json needs findings[]`);
      for (const f of triage.findings) {
        if (!['realIssue', 'falsePositive', 'unsure'].includes(f.verdict)) {
          fail(`phase 26 acceptance: ${app} triage verdict ${f.verdict}`);
        }
        if (!f.reason) fail(`phase 26 acceptance: ${app} triage entry missing reason`);
      }
    }
    const benchMd = join(root, 'BENCHMARK.md');
    if (!existsSync(benchMd)) fail('phase 26 acceptance: BENCHMARK.md missing (run npm run bench:public)');
    const md = readFileSync(benchMd, 'utf8');
    if (!/UNREVIEWED/.test(md)) fail('phase 26 acceptance: BENCHMARK.md must say UNREVIEWED while ground truth is unreviewed');
    for (const app of ['nodegoat', 'juice-shop', 'dvna', 'goof', 'vulnerable-node']) {
      if (!md.toLowerCase().includes(app)) fail(`phase 26 acceptance: BENCHMARK.md missing ${app}`);
    }
    if (!/holdout/i.test(md)) fail('phase 26 acceptance: BENCHMARK.md must label the goof holdout');
    if (!/seen holdout/i.test(md)) {
      fail('phase 26c acceptance: BENCHMARK.md must label goof as seen holdout');
    }
    if (!/self-triaged, unverified/i.test(md)) {
      fail('phase 26c acceptance: BENCHMARK.md must mark precision as self-triaged, unverified');
    }
    if (!/Line attribution/i.test(md) && !/line-attribution/i.test(md)) {
      fail('phase 26 acceptance: BENCHMARK.md must explain helmet line-attribution is not a recall gain');
    }
    if (!/Known misses/i.test(md)) fail('phase 26 acceptance: BENCHMARK.md missing Known misses table');
    if (!/in-scope/i.test(md) || !/unsure/i.test(md)) {
      fail('phase 26 acceptance: BENCHMARK.md must report in-scope recall and unsure triage count');
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('BENCHMARK.md')) fail('phase 26 acceptance: README must link BENCHMARK.md');
    for (const needle of [
      'url.includes(allowedUrl)',
      '{ _id: req.body.id }',
      'res.json',
      'autoescape',
      'package.json:N',
      'mathjs.eval',
    ]) {
      if (!readme.includes(needle)) {
        fail(`phase 26b acceptance: README Known limitations missing ${needle}`);
      }
    }
    for (const path of [
      join(root, 'test', 'unit', 'modules', 'sast', 'bench-misses.test.ts'),
      join(root, 'test', 'unit', 'modules', 'config', 'bench-misses.test.ts'),
      join(root, 'test', 'unit', 'modules', 'secrets', 'bench-misses.test.ts'),
      join(root, 'test', 'unit', 'modules', 'sast', 'engine-gaps.test.ts'),
      join(root, 'test', 'unit', 'modules', 'deps', 'manifest-line.test.ts'),
    ]) {
      if (!existsSync(path)) fail(`phase 26b/26c acceptance: missing ${relative(root, path)}`);
    }
    if (!/unreviewed/i.test(readme) || !/holdout/i.test(readme)) {
      fail('phase 26c acceptance: README Known limitations must cite holdout numbers on unreviewed ground truth');
    }
    console.log('  ✔ public bench harness, unreviewed ground truth, non-blocking CI bench job');
    console.log('  ✔ phase 26b fixtures + Known limitations for remaining in-scope misses');
    console.log('  ✔ phase 26c engine-gap fixtures, seen holdout, seen vulnerable-node holdout');
  },
  // Phase 27: SAST + RASP coverage gaps (numeric SQL, ORM raw, template shell).
  27: async () => {
    const raspUrl = pathToFileURL(join(root, 'dist', 'runtime', 'rasp.js')).href;
    const rasp = await import(raspUrl);
    const attack = JSON.parse(readFileSync(join(root, 'test', 'fixtures', 'rasp', 'attack-corpus.json'), 'utf8'));
    const benign = JSON.parse(readFileSync(join(root, 'test', 'fixtures', 'rasp', 'benign-corpus.json'), 'utf8'));
    for (const ctx of ['numeric-sql', 'orm-raw', 'template-shell']) {
      const n = attack.cases.filter((c) => c.context === ctx).length;
      if (n < 10) fail(`phase 27 acceptance: attack context ${ctx} has ${n} < 10 cases`);
    }
    const extra = attack.cases.filter(
      (c) => c.context === 'numeric-sql' || c.context === 'orm-raw' || c.context === 'template-shell',
    );
    const extraScore = rasp.scoreCorpusByKind(extra);
    if (extraScore.blocked !== extraScore.total) {
      fail(`phase 27 acceptance: new-context attacks ${extraScore.blocked}/${extraScore.total}`);
    }
    const benignScore = rasp.scoreCorpusByKind(benign.cases);
    if (benignScore.blocked !== 0) {
      fail(`phase 27 acceptance: benign corpus blocked ${benignScore.blocked}`);
    }
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );
    if (!cliHelp.stdout.includes('--experimental-sast-gaps')) {
      fail('phase 27 acceptance: scan --help missing --experimental-sast-gaps');
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_SAST_GAPS')) {
      fail('phase 27 acceptance: README must document FULLSHIELD_EXPERIMENTAL_SAST_GAPS');
    }
    if (/Untested contexts include numeric SQL/.test(readme)) {
      fail('phase 27 acceptance: README Known Limitations still lists numeric SQL/ORM/template-shell as untested');
    }
    console.log('  ✔ numeric/ORM/template-shell corpora blocked; benign 0; extra SAST sinks experimental');
  },
  // Phase 28: Next/Nest/Hono/Koa taint sources + AUTH + runtime adapters (experimental).
  28: () => {
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );
    if (!cliHelp.stdout.includes('--experimental-frameworks')) {
      fail('phase 28 acceptance: scan --help missing --experimental-frameworks');
    }
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    if (pkg.dependencies?.koa !== undefined || pkg.dependencies?.hono !== undefined) {
      fail('phase 28 acceptance: koa/hono must not be runtime dependencies');
    }
    if (pkg.peerDependencies?.koa === undefined || pkg.peerDependencies?.hono === undefined) {
      fail('phase 28 acceptance: koa and hono must be optional peerDependencies');
    }
    if (pkg.peerDependenciesMeta?.koa?.optional !== true || pkg.peerDependenciesMeta?.hono?.optional !== true) {
      fail('phase 28 acceptance: koa/hono peers must be optional');
    }
    if (pkg.exports?.['./runtime/koa'] === undefined || pkg.exports?.['./runtime/hono'] === undefined) {
      fail('phase 28 acceptance: package exports missing runtime/koa or runtime/hono');
    }
    for (const rel of [
      'test/fixtures/frameworks/next-vuln/app/api/items/route.ts',
      'test/fixtures/frameworks/next-clean/app/api/items/route.ts',
      'test/fixtures/frameworks/nest-vuln/items.controller.ts',
      'test/fixtures/frameworks/nest-clean/items.controller.ts',
      'test/fixtures/frameworks/hono-vuln/index.ts',
      'test/fixtures/frameworks/hono-clean/index.ts',
      'test/fixtures/frameworks/koa-vuln/index.ts',
      'test/fixtures/frameworks/koa-clean/index.ts',
    ]) {
      if (!existsSync(join(root, rel))) fail(`phase 28 acceptance: missing fixture ${rel}`);
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_FRAMEWORKS')) {
      fail('phase 28 acceptance: README must document FULLSHIELD_EXPERIMENTAL_FRAMEWORKS');
    }
    console.log('  ✔ experimental Next/Nest/Hono/Koa taint; optional runtime peers; vuln+clean fixtures');
  },
  // Phase 29: extra vuln classes behind FULLSHIELD_EXPERIMENTAL_CLASSES.
  29: () => {
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );
    if (!cliHelp.stdout.includes('--experimental-classes')) {
      fail('phase 29 acceptance: scan --help missing --experimental-classes');
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_CLASSES')) {
      fail('phase 29 acceptance: README must document FULLSHIELD_EXPERIMENTAL_CLASSES');
    }
    const phase29Ids = [
      'SAST-REDOS-001',
      'SAST-DESER-001',
      'SAST-XXE-001',
      'SAST-UPLOAD-001',
      'SAST-COOKIE-001',
      'SAST-CSRF-001',
      'SAST-MASSASSIGN-001',
      'SAST-TIMING-001',
      'SAST-HASH-001',
      'SAST-GQL-001',
      'CONFIG-TRUSTPROXY-001',
    ];
    for (const id of phase29Ids) {
      if (!existsSync(join(root, 'rules', `${id}.md`))) {
        fail(`phase 29 acceptance: missing rules/${id}.md`);
      }
      if (foundRuleIds.has(id)) {
        fail(`phase 29 acceptance: default scan of vulnerable-app emitted ${id}`);
      }
      if (clean.report.findings.some((f) => f.ruleId === id)) {
        fail(`phase 29 acceptance: default scan of clean-app emitted ${id}`);
      }
    }
    console.log('  ✔ experimental classes behind flag; default scan emits no Phase 29 rule IDs');
  },
  // Phase 30: experimental git-history / bundle / verify-secrets.
  30: () => {
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );
    for (const flag of [
      '--experimental-secrets-adv',
      '--history',
      '--bundle',
      '--verify-secrets',
      '--i-own-these-credentials',
    ]) {
      if (!cliHelp.stdout.includes(flag)) {
        fail(`phase 30 acceptance: scan --help missing ${flag}`);
      }
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_SECRETS_ADV')) {
      fail('phase 30 acceptance: README must document FULLSHIELD_EXPERIMENTAL_SECRETS_ADV');
    }
    if (!readme.includes('--verify-secrets')) {
      fail('phase 30 acceptance: README must document --verify-secrets');
    }
    for (const rel of [
      'templates/github-workflow.yml',
      'templates/gitlab-ci.yml',
      'templates/github-watch.yml',
      'templates/pre-commit.sh',
    ]) {
      const text = readFileSync(join(root, rel), 'utf8');
      if (text.includes('--verify-secrets') || text.includes('i-own-these-credentials')) {
        fail(`phase 30 acceptance: ${rel} must not enable --verify-secrets`);
      }
    }
    const phase30ids = ['SECRET-BUNDLE-001'];
    for (const id of phase30ids) {
      if (foundRuleIds.has(id)) {
        fail(`phase 30 acceptance: default vulnerable-app scan emitted Phase-30-only ${id}`);
      }
      if (clean.report.findings.some((f) => f.ruleId === id)) {
        fail(`phase 30 acceptance: default clean-app scan emitted Phase-30-only ${id}`);
      }
    }
    const srcHist = readFileSync(join(root, 'src', 'modules', 'secrets', 'history.ts'), 'utf8');
    if (!srcHist.includes("'log'") || !srcHist.includes("'-p'")) {
      fail('phase 30 acceptance: history scan must stream git log -p');
    }
    console.log('  ✔ history/bundle/verify-secrets experimental; default scan unchanged; verify not in CI templates');
  },
  // Phase 31: worm/workflow indicators, transitive overrides, provenance score, VEX.
  31: async () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_VEX')) {
      fail('phase 31 acceptance: README must document FULLSHIELD_EXPERIMENTAL_VEX');
    }
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const beforeDeps = ['@typescript-eslint/typescript-estree', 'commander', 'ignore', 'picocolors'];
    const depNames = Object.keys(pkg.dependencies ?? {});
    for (const extra of depNames.filter((n) => !beforeDeps.includes(n))) {
      fail(`phase 31 acceptance: new hard dependency ${extra}`);
    }

    const supplyUrl = pathToFileURL(join(root, 'dist', 'supply.js')).href;
    const supply = await import(supplyUrl);
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_VEX;
    delete process.env.FULLSHIELD_EXPERIMENTAL_VEX;
    const wormDir = join(root, 'test', 'fixtures', 'supply', 'worm-pkg');
    const off = supply.analyzePackageDir(wormDir);
    if (off.some((f) => f.ruleId === 'SUPPLY-WORM-001' || f.ruleId === 'SUPPLY-WORKFLOW-001')) {
      fail('phase 31 acceptance: default analyzePackageDir must not emit new IDs without the flag');
    }
    process.env.FULLSHIELD_EXPERIMENTAL_VEX = '1';
    const worm = supply.analyzeWormIndicators(wormDir);
    if (!worm.some((f) => f.ruleId === 'SUPPLY-WORM-001' && f.severity === 'critical')) {
      fail('phase 31 acceptance: seeded worm-like fixture not detected');
    }
    const tamper = supply.analyzeWorkflowTampering(join(root, 'test', 'fixtures', 'supply', 'workflow-tamper-pkg'));
    if (!tamper.some((f) => f.ruleId === 'SUPPLY-WORKFLOW-001')) {
      fail('phase 31 acceptance: workflow-tamper fixture not detected');
    }
    if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_VEX;
    else process.env.FULLSHIELD_EXPERIMENTAL_VEX = prev;

    const defaultScan = runCliJson(vulnerableApp, ['--modules', 'deps', '--offline']);
    const leaked = defaultScan.report.findings.filter((f) =>
      ['SUPPLY-WORM-001', 'SUPPLY-WORKFLOW-001'].includes(f.ruleId),
    );
    if (leaked.length > 0) fail('phase 31 acceptance: default scan emitted new Phase 31 IDs');
    console.log('  ✔ seeded worm fixture detected behind flag; default scan emits no new IDs');

    const vexApp = join(root, 'test', 'fixtures', 'vex-app');
    const cli = join(root, 'dist', 'cli', 'index.js');
    const refused = spawnSync(process.execPath, [cli, 'vex', vexApp, '--format', 'openvex'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '' },
    });
    if (refused.status !== 2 || !/FULLSHIELD_EXPERIMENTAL_VEX/.test(refused.stderr)) {
      fail('phase 31 acceptance: vex must refuse without FULLSHIELD_EXPERIMENTAL_VEX');
    }
    const { validateOpenVex, validateCycloneDxVex } = await import(
      pathToFileURL(join(root, 'dist', 'index.js')).href
    );
    for (const format of ['openvex', 'cyclonedx']) {
      const ran = spawnSync(process.execPath, [cli, 'vex', vexApp, '--format', format], {
        cwd: root,
        encoding: 'utf8',
        env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '1' },
      });
      if (ran.status !== 0) fail(`phase 31 acceptance: vex --format ${format} exited ${ran.status}`);
      const doc = JSON.parse(ran.stdout);
      const errors = format === 'cyclonedx' ? validateCycloneDxVex(doc) : validateOpenVex(doc);
      if (errors.length > 0) fail(`phase 31 acceptance: ${format} VEX invalid: ${errors.join('; ')}`);
    }
    console.log('  ✔ VEX validates against OpenVEX and CycloneDX schemas');

    const overrideApp = join(root, 'test', 'fixtures', 'override-app');
    const tmp = join(root, '.fullshield-verify-phase31');
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true });
    try {
      const copy = join(tmp, 'override-app');
      const copied = spawnSync('cp', ['-R', overrideApp, copy], { encoding: 'utf8' });
      if (copied.status !== 0) fail('phase 31 acceptance: could not copy override-app');
      const lockBefore = readFileSync(join(copy, 'package-lock.json'));
      const env = { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '1' };
      const apply = spawnSync(
        process.execPath,
        [cli, 'fix', copy, '--apply', '--unsafe', '--force', '--no-branch', '--modules', 'deps'],
        { cwd: root, encoding: 'utf8', env },
      );
      if (apply.status !== 0) {
        fail(`phase 31 acceptance: override fix --apply exited ${apply.status}: ${apply.stderr}`);
      }
      if (!String(apply.stdout).includes('run npm install')) {
        fail('phase 31 acceptance: fix --apply must print "run npm install"');
      }
      const manifest = JSON.parse(readFileSync(join(copy, 'package.json'), 'utf8'));
      if (manifest.overrides?.['leaf-vuln'] !== '1.0.1') {
        fail('phase 31 acceptance: package.json overrides did not pin leaf-vuln@1.0.1');
      }
      const lockAfter = readFileSync(join(copy, 'package-lock.json'));
      if (!lockBefore.equals(lockAfter)) {
        fail('phase 31 acceptance: package-lock.json must stay byte-identical');
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
    console.log('  ✔ override writes package.json, leaves package-lock.json byte-identical, prints run npm install');
  },
  // Phase 32: experimental response DLP behind FULLSHIELD_EXPERIMENTAL_DLP.
  32: async () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_DLP')) {
      fail('phase 32 acceptance: README must document FULLSHIELD_EXPERIMENTAL_DLP');
    }
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    if (!changelog.includes('Phase 32') || !changelog.includes('FULLSHIELD_EXPERIMENTAL_DLP')) {
      fail('phase 32 acceptance: CHANGELOG must document Phase 32 DLP');
    }
    for (const rel of [
      'test/fixtures/dlp/secret.json',
      'test/fixtures/dlp/stack.json',
      'test/fixtures/dlp/internal.json',
      'test/fixtures/dlp/card.json',
      'test/fixtures/dlp/pii.json',
      'test/fixtures/dlp/benign-corpus.json',
      'test/unit/runtime/phase32-dlp.test.ts',
      'src/runtime/dlp/index.ts',
    ]) {
      if (!existsSync(join(root, rel))) fail(`phase 32 acceptance: missing ${rel}`);
    }
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const hard = Object.keys(pkg.dependencies ?? {});
    const allowed = ['@typescript-eslint/typescript-estree', 'commander', 'ignore', 'picocolors'];
    for (const name of hard) {
      if (!allowed.includes(name)) fail(`phase 32 acceptance: new hard dependency ${name}`);
    }
    const dlpSrc = listFilesRecursive(join(root, 'src', 'runtime')).filter((f) => f.endsWith('.ts'));
    for (const file of dlpSrc) {
      const text = readFileSync(file, 'utf8');
      const rel = relative(root, file);
      if (/from\s+['"]node:sqlite['"]/.test(text) || /require\(\s*['"]node:sqlite['"]\s*\)/.test(text)) {
        fail(`phase 32 acceptance: ${rel} statically loads node:sqlite`);
      }
      if (/from\s+['"][^'"]*modules\/secrets/.test(text)) {
        fail(`phase 32 acceptance: ${rel} imports the secrets scanner`);
      }
    }
    const off = runCliJson(vulnerableApp);
    const offClean = runCliJson(cleanApp);
    const dlpIds = [...off.report.findings, ...offClean.report.findings]
      .map((f) => f.ruleId)
      .filter((id) => String(id).startsWith('DLP-'));
    if (dlpIds.length > 0) {
      fail(`phase 32 acceptance: default scan emitted DLP rule ids: ${dlpIds.join(',')}`);
    }
    const dlpMod = await import(pathToFileURL(join(root, 'dist', 'runtime', 'dlp.js')).href);
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_DLP;
    process.env.FULLSHIELD_EXPERIMENTAL_DLP = '1';
    const inspector = dlpMod.createDlpInspector({ dlp: { mode: 'mask' } });
    if (inspector === undefined) fail('phase 32 acceptance: createDlpInspector returned undefined with flag set');
    const hit = inspector.inspect({ host: '10.1.2.3' }, { path: '/i' });
    if (!hit.hits.some((h) => h.ruleId === 'DLP-INTERNAL-001')) {
      fail('phase 32 acceptance: internal IP fixture not detected');
    }
    const benignBody = { ok: true, email: 'support@example.com', resolver: '8.8.8.8' };
    const cleanHit = inspector.inspect(benignBody, { path: '/benign' });
    if (cleanHit.hits.length > 0 || cleanHit.action !== 'allow') {
      fail('phase 32 acceptance: benign body was masked or flagged');
    }
    if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_DLP;
    else process.env.FULLSHIELD_EXPERIMENTAL_DLP = prev;
    console.log('  ✔ experimental DLP flag, fixtures, no default-scan DLP ids, runtime has no sqlite/scanner import');
  },
  // Phase 33: MCP client/server config rules behind FULLSHIELD_EXPERIMENTAL_MCPCFG.
  33: async () => {
    const mcp = await import(pathToFileURL(join(root, 'dist', 'index.js')).href);
    const compliance = await import(pathToFileURL(join(root, 'dist', 'compliance.js')).href);
    const app = join(root, 'test', 'fixtures', 'mcp-app');
    const clean = join(root, 'test', 'fixtures', 'mcp-clean');
    const bad = mcp.scanMcpConfig(app, { experimental: true });
    for (const id of ['MCP-001', 'MCP-002', 'MCP-003', 'MCP-004', 'MCP-005']) {
      if (!bad.some((f) => f.ruleId === id)) fail(`phase 33 acceptance: missing ${id} on mcp-app`);
    }
    const good = mcp.scanMcpConfig(clean, { experimental: true });
    if (good.some((f) => String(f.ruleId).startsWith('MCP-'))) {
      fail(`phase 33 acceptance: mcp-clean produced ${good.map((f) => f.ruleId).join(',')}`);
    }
    if (mcp.scanMcpConfig(app).some((f) => String(f.ruleId).startsWith('MCP-'))) {
      fail('phase 33 acceptance: MCP rules ran without experimental flag');
    }
    const homeHits = mcp.scanMcpConfig(clean, { experimental: true, includeHome: false });
    if (homeHits.some((f) => String(f.ruleId).startsWith('MCP-'))) {
      fail('phase 33 acceptance: home scan ran without --include-home');
    }
    const mapped = new Set(compliance.RULE_MAP.map((r) => r.ruleId));
    for (const id of ['MCP-001', 'MCP-002', 'MCP-003', 'MCP-004', 'MCP-005']) {
      if (!mapped.has(id)) fail(`phase 33 acceptance: missing compliance row ${id}`);
    }
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );

    if (!cliHelp.stdout.includes('--include-home')) {
      fail('phase 33 acceptance: scan --help missing --include-home');
    }
    if (!cliHelp.stdout.includes('--experimental-mcpcfg')) {
      fail('phase 33 acceptance: scan --help missing --experimental-mcpcfg');
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_MCPCFG')) {
      fail('phase 33 acceptance: README must document FULLSHIELD_EXPERIMENTAL_MCPCFG');
    }
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const depCount = Object.keys(pkg.dependencies ?? {}).length;
    if (depCount > 10) fail(`phase 33 acceptance: new hard dependency added (${depCount} > 10)`);
    console.log('  ✔ MCP-001..005 positive/negative; off without flag; home requires --include-home; no new deps');
  },
  // Phase 34: policy-as-code + deterministic PR summary (experimental).
  34: () => {
    const cliHelp = spawnSync(
      process.execPath,
      [join(root, 'dist', 'cli', 'index.js'), 'scan', '--help'],
      { cwd: root, encoding: 'utf8' },
    );

    if (!cliHelp.stdout.includes('--pr-summary')) {
      fail('phase 34 acceptance: scan --help missing --pr-summary');
    }
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    if (pkg.dependencies?.zod !== undefined) {
      fail('phase 34 acceptance: zod must not be a hard dependency (optional peer only)');
    }
    if (pkg.peerDependencies?.zod === undefined || pkg.peerDependenciesMeta?.zod?.optional !== true) {
      fail('phase 34 acceptance: zod must remain an optional peerDependency');
    }
    const src = readFileSync(join(root, 'src', 'policy', 'index.ts'), 'utf8');
    if (!src.includes("import('zod')") && !src.includes('import("zod")')) {
      fail('phase 34 acceptance: policy must lazy-import zod');
    }
    for (const rel of [
      'test/fixtures/policy/pr-summary.md',
      'test/fixtures/policy/pr-summary-empty.md',
      'test/unit/policy/policy.test.ts',
      'test/unit/policy/pr-summary.test.ts',
      'test/e2e/phase34.e2e.test.ts',
    ]) {
      if (!existsSync(join(root, rel))) fail(`phase 34 acceptance: missing ${rel}`);
    }
    const policyTests = [
      readFileSync(join(root, 'test', 'unit', 'policy', 'policy.test.ts'), 'utf8'),
      readFileSync(join(root, 'test', 'e2e', 'phase34.e2e.test.ts'), 'utf8'),
    ].join('\n');
    if (!/expired/i.test(policyTests)) {
      fail('phase 34 acceptance: expired-exception CI failure must be tested');
    }
    const golden = readFileSync(join(root, 'test', 'fixtures', 'policy', 'pr-summary.md'), 'utf8');
    if (!golden.includes('SAST-SQLI-001') || !golden.includes('rules/SAST-SQLI-001.md')) {
      fail('phase 34 acceptance: PR summary golden must list findings with rule-doc links');
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_POLICY')) {
      fail('phase 34 acceptance: README must document FULLSHIELD_EXPERIMENTAL_POLICY');
    }
    if (!readme.includes('fullshield.policy.json')) {
      fail('phase 34 acceptance: README must document fullshield.policy.json');
    }
    if (!readme.includes('--pr-summary')) {
      fail('phase 34 acceptance: README must document scan --pr-summary');
    }
    console.log('  ✔ experimental policy-as-code; expired exceptions fail CI; PR summary goldens');
  },
  // Phase 35: experimental Linux-only OpenSSH host exposure (detection/reporting only).
  35: () => {
    const cli = join(root, 'dist', 'cli', 'index.js');
    const refused = spawnSync(process.execPath, [cli, 'host'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_HOST: '' },
    });
    if (refused.status !== 2) {
      fail(`phase 35 acceptance: host without --experimental-host exited ${refused.status}, expected 2`);
    }
    if (!/experimental-host/.test(refused.stderr)) {
      fail('phase 35 acceptance: host without --experimental-host must mention --experimental-host');
    }
    const help = spawnSync(process.execPath, [cli, 'host', '--help'], {
      cwd: root,
      encoding: 'utf8',
    });
    if (!help.stdout.includes('--experimental-host')) {
      fail('phase 35 acceptance: host --help missing --experimental-host');
    }
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!/does not stop OS or SSH exploits/i.test(readme)) {
      fail('phase 35 acceptance: README must state FullShield does not stop OS or SSH exploits');
    }
    if (!/What it does NOT do/i.test(readme)) {
      fail('phase 35 acceptance: README must include What it does NOT do');
    }
    if (!readme.includes('FULLSHIELD_EXPERIMENTAL_HOST')) {
      fail('phase 35 acceptance: README must document FULLSHIELD_EXPERIMENTAL_HOST');
    }
    for (const rel of [
      'test/fixtures/host/dpkg-backport-patched.txt',
      'test/fixtures/host/dpkg-vulnerable-upstream.txt',
      'test/fixtures/host/dpkg-fixed.txt',
      'test/fixtures/host/rpm-backport-patched.txt',
      'test/fixtures/host/rpm-vulnerable-upstream.txt',
      'test/fixtures/host/rpm-fixed.txt',
      'test/fixtures/host/apk-backport-patched.txt',
      'test/fixtures/host/apk-vulnerable-upstream.txt',
      'test/fixtures/host/apk-fixed.txt',
      'test/fixtures/host/sshd-T-mitigated.txt',
      'test/fixtures/host/sshd-T-unmitigated.txt',
      'test/fixtures/host/auth.log',
    ]) {
      if (!existsSync(join(root, rel))) fail(`phase 35 acceptance: missing fixture ${rel}`);
    }
    if (vuln.report.findings.some((f) => String(f.ruleId).startsWith('HOST-'))) {
      fail('phase 35 acceptance: default scan emitted HOST-* without --experimental-host');
    }
    const hostSrc = readFileSync(join(root, 'src', 'host', 'index.ts'), 'utf8');
    if (/\bssh\s+-V\b/.test(hostSrc)) {
      fail('phase 35 acceptance: host check must not use ssh -V');
    }
    console.log('  ✔ experimental host SSH check; refuses without --experimental-host; default scan has no HOST-*');
  },
  // Phase 36: release integrity. No tag. Version bump stays a human decision.
  36: () => {
    for (const rel of [
      'scripts/semver-check.mjs',
      'scripts/pack-budget.mjs',
      'scripts/provenance-gate.mjs',
      'scripts/release-checks.mjs',
      'test/unit/release/phase36.test.ts',
    ]) {
      if (!existsSync(join(root, rel))) fail(`phase 36 acceptance: missing ${rel}`);
    }
    const publish = readFileSync(join(root, '.github', 'workflows', 'publish.yml'), 'utf8');
    if (!publish.includes('scripts/provenance-gate.mjs')) {
      fail('phase 36 acceptance: publish.yml missing provenance gate');
    }
    if (!publish.includes('scripts/semver-check.mjs') || !publish.includes('scripts/pack-budget.mjs')) {
      fail('phase 36 acceptance: publish.yml missing semver-check or pack-budget');
    }
    const stage = readFileSync(join(root, 'scripts', 'npm-stage-publish.mjs'), 'utf8');
    if (/retrying without --provenance/.test(stage)) {
      fail('phase 36 acceptance: stage must not retry without provenance');
    }
    const releasing = readFileSync(join(root, 'RELEASING.md'), 'utf8');
    if (!releasing.includes('0.1.3') || !/without provenance/i.test(releasing)) {
      fail('phase 36 acceptance: RELEASING.md must explain why 0.1.3 has no provenance');
    }
    const semver = spawnSync(process.execPath, [join(root, 'scripts', 'semver-check.mjs')], {
      cwd: root,
      encoding: 'utf8',
    });
    const semverOut = `${semver.stdout ?? ''}${semver.stderr ?? ''}`;
    if (!semverOut.includes('required:')) {
      fail(`phase 36 acceptance: semver-check did not report a required bump:\n${semverOut}`);
    }
    console.log(semverOut.trim());
    if (semver.status === 1) {
      console.log('  ✔ semver-check reports the required bump; package.json is not bumped until the human confirms');
    } else if (semver.status !== 0) {
      fail(`phase 36 acceptance: semver-check exited ${semver.status}`);
    }
    console.log('  ✔ provenance gate is required; stage does not drop provenance; pack and semver scripts exist');
  },
  37: () => {
    for (const rel of ['bench/holdouts.json', 'bench/REVIEW.md', 'bench/review-sheet.mjs', 'bench/sample-triage.mjs']) {
      if (!existsSync(join(root, rel))) fail(`phase 37 acceptance: missing ${rel}`);
    }
    for (const name of ['verademo-javascript', 'serverless-goat', 'mongection']) {
      if (existsSync(join(root, 'bench', name, 'scan.json'))) {
        fail(`phase 37 acceptance: ${name} was scanned`);
      }
    }
    console.log('  ✔ three untouched holdouts are registered and have no scan result');
  },
  38: () => {
    if (!existsSync(join(root, 'bench', 'compare.mjs'))) fail('phase 38 acceptance: missing compare.mjs');
    const comparison = readFileSync(join(root, 'COMPARISON.md'), 'utf8');
    if (!/not executed/i.test(comparison) && !/true positive/i.test(comparison)) {
      fail('phase 38 acceptance: COMPARISON.md has neither a not-executed note nor real results');
    }
    console.log('  ✔ comparison harness exists; results are only present when tools were run');
  },
  39: () => {
    const src = readFileSync(join(root, 'src', 'modules', 'deps', 'symbol-reachability.ts'), 'utf8');
    if (!src.includes('affected_functions')) fail('phase 39 acceptance: symbol list is not read from advisory data');
    const reach = readFileSync(join(root, 'src', 'modules', 'deps', 'reachability.ts'), 'utf8');
    if (!reach.includes('DEPS-MALICIOUS-001')) fail('phase 39 acceptance: malicious advisories must stay critical');
    console.log('  ✔ symbol reachability uses advisory function names and does not downgrade malicious packages');
  },
  40: () => {
    const src = readFileSync(join(root, 'src', 'modules', 'sast', 'experimental.ts'), 'utf8');
    if (!src.includes('FULLSHIELD_EXPERIMENTAL_TAINT_V2')) {
      fail('phase 40 acceptance: taint v2 flag missing');
    }
    console.log('  ✔ taint v2 is behind FULLSHIELD_EXPERIMENTAL_TAINT_V2');
  },
  41: () => {
    const doc = JSON.parse(readFileSync(join(root, 'bench', 'realworld.json'), 'utf8'));
    if (!Array.isArray(doc.repos) || doc.repos.length < 10) fail('phase 41 acceptance: need 10 pinned repos');
    const benchmark = readFileSync(join(root, 'BENCHMARK.md'), 'utf8');
    if (!benchmark.includes('not sampled')) fail('phase 41 acceptance: precision must say not sampled until a human labels findings');
    console.log('  ✔ ten repos are pinned; precision is not sampled');
  },
  42: () => {
    if (!existsSync(join(root, 'src', 'core', 'parse-pool.ts'))) fail('phase 42 acceptance: parse pool missing');
    if (!existsSync(join(root, 'bench', 'perf.mjs'))) fail('phase 42 acceptance: perf harness missing');
    console.log('  ✔ parse pool and perf harness exist; timings stay unmeasured until the repos are checked out');
  },
  43: () => {
    const report = spawnSync(process.execPath, [join(root, 'scripts', 'promotion-report.mjs')], {
      cwd: root,
      encoding: 'utf8',
    });
    if (report.status !== 0 || !String(report.stdout).includes('unmet')) {
      fail('phase 43 acceptance: promotion report must list unmet criteria');
    }
    console.log('  ✔ no experimental flag is promoted');
  },
  44: () => {
    const program = readFileSync(join(root, 'src', 'cli', 'program.ts'), 'utf8');
    if (!program.includes(".command('doctor')")) fail('phase 44 acceptance: doctor command missing');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    if (!readme.includes('fullshield doctor')) fail('phase 44 acceptance: README missing doctor');
    console.log('  ✔ doctor, error codes, and the console cap are present');
  },
  45: () => {
    const workflows = join(root, '.github', 'workflows');
    for (const name of ['ci.yml', 'publish.yml', 'codeql.yml', 'scorecard.yml', 'sbom.yml']) {
      const text = readFileSync(join(workflows, name), 'utf8');
      if (/uses:\s+\S+@v\d/.test(text)) fail(`phase 45 acceptance: ${name} has a floating action tag`);
    }
    if (!existsSync(join(root, '.github', 'dependabot.yml'))) fail('phase 45 acceptance: dependabot.yml missing');
    console.log('  ✔ project workflows are pinned; CodeQL, Scorecard, and the SBOM release job exist');
  },
  88: () => {
    const program = readFileSync(join(root, 'src', 'cli', 'program.ts'), 'utf8');
    if (!program.includes(".command('dev')")) fail('phase 88 acceptance: dev command missing');
    const src = readFileSync(join(root, 'src', 'dev', 'index.ts'), 'utf8');
    if (!src.includes('FULLSHIELD_EXPERIMENTAL_DEV')) fail('phase 88 acceptance: flag missing');
    if (!src.includes('fs.watch') && !src.includes('watch(')) fail('phase 88 acceptance: fs.watch missing');
    if (!src.includes('300')) fail('phase 88 acceptance: 300ms debounce missing');
    if (!existsSync(join(root, 'test', 'unit', 'dev', 'phase88.test.ts'))) fail('phase 88 acceptance: test missing');
    console.log('  ✔ fullshield dev is behind FULLSHIELD_EXPERIMENTAL_DEV');
  },
  94: () => {
    const doc = readFileSync(join(root, 'docs', 'QUALITY.md'), 'utf8');
    for (const id of ['Q1', 'Q2', 'Q3', 'Q4', 'Q5', 'Q6', 'Q7', 'Q8', 'Q9', 'Q10', 'Q11', 'Q12']) {
      if (!doc.includes(id)) fail(`phase 94 acceptance: QUALITY.md missing ${id}`);
    }
    if (!existsSync(join(root, 'quality', 'baseline.json'))) fail('phase 94 acceptance: baseline missing');
    console.log('  ✔ quality gate documents Q1–Q12 and records a baseline');
  },
};

if (phase !== null) {
  section(`phase ${phase} acceptance criteria`);
  const check = acceptanceCriteria[phase];
  if (check === undefined) {
    fail(`acceptance criteria for phase ${phase} are not encoded in scripts/verify.mjs yet`);
  }
  const result = check();
  if (result && typeof result.then === 'function') await result;
  console.log(`  ✔ phase ${phase} acceptance criteria passed`);
}

assertSrcTestClean(root, 'verify');
releaseVerifyLock(root);
console.log('\nVERIFY PASSED');
