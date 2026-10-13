#!/usr/bin/env node
/**
 * Mutation smoke test (SECURITY_SCANNER_SPEC.md §0.1 step 5).
 *
 * For each SAST/secrets rule file, temporarily disable its detection (every
 * `ctx.report(` call becomes a no-op) and run the full test suite. If the
 * suite STILL passes with the rule disabled, the rule's tests are fake and
 * this script fails the verify run.
 *
 * Convention established in Phase 1: every rule lives in
 * src/modules/{sast,secrets}/rules/*.ts and reports findings exclusively via
 * `ctx.report(...)`. Phase 1 ships zero rules, so this script verifies the
 * convention directories and exits cleanly when no rules exist yet.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';

const RULE_DIRS = [join('src', 'modules', 'sast', 'rules'), join('src', 'modules', 'secrets', 'rules')];
const REPORT_CALL = 'ctx.report(';
// `void(...)` is a type-safe no-op for any argument list, so the mutant still
// compiles and the TEST run (not the build) must be what catches it.
const DISABLED_CALL = 'void(';

function collectRuleFiles() {
  const files = [];
  for (const dir of RULE_DIRS) {
    const full = join(root, dir);
    if (!existsSync(full)) continue;
    for (const entry of readdirSync(full, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.ts') && entry.name !== 'index.ts') {
        files.push(join(full, entry.name));
      }
    }
  }
  return files;
}

function runSuite() {
  const build = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['run', 'build'], {
    cwd: root,
    encoding: 'utf8',
    shell: isWindows,
  });
  if (build.status !== 0) return { status: build.status, stage: 'build' };
  const test = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['test'], {
    cwd: root,
    encoding: 'utf8',
    shell: isWindows,
  });
  return { status: test.status, stage: 'test' };
}

const ruleFiles = collectRuleFiles();
if (ruleFiles.length === 0) {
  console.log(
    'mutation-smoke: no SAST/secrets rule files exist yet (expected before Phase 2); nothing to mutate.',
  );
  process.exit(0);
}

const fakeTested = [];
for (const file of ruleFiles) {
  const rel = relative(root, file);
  const original = readFileSync(file, 'utf8');
  if (!original.includes(REPORT_CALL)) {
    console.error(
      `mutation-smoke: ${rel} does not call ctx.report( — it violates the rule convention and cannot be mutation-tested.`,
    );
    process.exit(1);
  }
  const mutated = original.replaceAll(REPORT_CALL, DISABLED_CALL);
  console.log(`mutation-smoke: disabling detection in ${rel} ...`);
  writeFileSync(file, mutated);
  let result;
  try {
    result = runSuite();
  } finally {
    writeFileSync(file, original);
  }
  if (result.status === 0) {
    fakeTested.push(rel);
    console.error(`  ✖ suite still passes with ${rel} disabled — its tests are fake`);
  } else {
    console.log(`  ✔ suite fails (${result.stage}) when ${rel} is disabled`);
  }
}

// Rebuild so dist/ matches the restored sources for any later steps.
spawnSync(isWindows ? 'npm.cmd' : 'npm', ['run', 'build'], {
  cwd: root,
  stdio: 'ignore',
  shell: isWindows,
});

if (fakeTested.length > 0) {
  console.error(`mutation-smoke FAILED: ${fakeTested.join(', ')}`);
  process.exit(1);
}
console.log(`mutation-smoke: ${ruleFiles.length} rule(s) verified.`);
