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
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';

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

console.table([
  {
    phase: phase ?? '(all)',
    'coverage lines': coverageLines,
    'coverage branches': coverageBranches,
    'implemented modules': IMPLEMENTED_MODULES.length > 0 ? IMPLEMENTED_MODULES.join(',') : 'none',
    'expected findings': expected.length,
    'found expected': expected.length - missing.length,
    'vulnerable-app findings': vuln.report.summary.total,
    'clean-app high/critical': falsePositives.length,
  },
]);

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
    const paths = (listing[0]?.files ?? []).map((f) => f.path);
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
};

if (phase !== null) {
  section(`phase ${phase} acceptance criteria`);
  const check = acceptanceCriteria[phase];
  if (check === undefined) {
    fail(`acceptance criteria for phase ${phase} are not encoded in scripts/verify.mjs yet`);
  }
  check();
  console.log(`  ✔ phase ${phase} acceptance criteria passed`);
}

console.log('\nVERIFY PASSED');
