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
import { existsSync, readFileSync, readdirSync } from 'node:fs';
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

const { IMPLEMENTED_MODULES } = await import(
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
