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

const EXTRA_TARGETS = [
  {
    name: 'EDGE-*',
    file: join(root, 'src', 'modules', 'edge', 'index.ts'),
    apply: (src) => {
      if (!src.includes('findings.push(')) {
        throw new Error('EDGE findings.push site missing');
      }
      return src.replaceAll('findings.push(', 'void (');
    },
  },
  {
    name: 'AI-INJECT-001',
    file: join(root, 'src', 'ai', 'injection.ts'),
    apply: (src) => {
      if (!src.includes('findings.push(')) {
        throw new Error('AI-INJECT-001 findings.push site missing');
      }
      return src.replaceAll('findings.push(', 'void (');
    },
  },
  {
    name: 'DEPS-NOLOCK-001',
    file: join(root, 'src', 'modules', 'deps', 'index.ts'),
    apply: (src) => {
      if (!src.includes('const findings: Finding[] = [noLockFinding()];')) {
        throw new Error('DEPS-NOLOCK-001 site missing');
      }
      return src.replace(
        'const findings: Finding[] = [noLockFinding()];',
        'const findings: Finding[] = [];',
      );
    },
  },
  {
    name: 'interproc taint',
    file: join(root, 'src', 'modules', 'sast', 'interproc.ts'),
    apply: (src) => {
      if (!src.includes('args.findings.push(')) {
        throw new Error('interproc pushSinkFinding site missing');
      }
      return src.replaceAll('args.findings.push(', 'void (');
    },
  },
  {
    name: 'RASP structure-change',
    file: join(root, 'src', 'runtime', 'rasp', 'decide.ts'),
    apply: (src) => {
      if (!src.includes('const hit = detectStructureChange')) {
        throw new Error('RASP decideSink site missing');
      }
      return src.replace('const hit = detectStructureChange', 'const hit = false && detectStructureChange');
    },
  },
  {
    name: 'RASP-HONEY-001',
    file: join(root, 'src', 'runtime', 'rasp', 'honey.ts'),
    apply: (src) => {
      if (!src.includes('return (DECOY_ROUTES as readonly string[]).includes(p);')) {
        throw new Error('honey route site missing');
      }
      return src.replace('return (DECOY_ROUTES as readonly string[]).includes(p);', 'return false;');
    },
  },
  {
    name: 'SUPPLY-CHAINC2-001',
    file: join(root, 'src', 'supply', 'campaign.ts'),
    apply: (src) => {
      if (!src.includes('if (hasChain && hasNet)')) {
        throw new Error('SUPPLY-CHAINC2-001 site missing');
      }
      return src.replace('if (hasChain && hasNet)', 'if (false && hasChain && hasNet)');
    },
  },
  {
    name: 'SUPPLY-NPMRC-NET-001',
    file: join(root, 'src', 'supply', 'index.ts'),
    apply: (src) => {
      if (!src.includes('if (readsNpmrc && hasNet)')) {
        throw new Error('SUPPLY-NPMRC-NET-001 site missing');
      }
      return src.replace('if (readsNpmrc && hasNet)', 'if (false && readsNpmrc && hasNet)');
    },
  },
  {
    name: 'confirm scope lock',
    file: join(root, 'src', 'confirm', 'index.ts'),
    apply: (src) => {
      if (!src.includes('if (isLiteralLocal(rawHost) && isLiteralLocal(host)) return;')) {
        throw new Error('confirm scope lock site missing');
      }
      return src.replace(
        'if (isLiteralLocal(rawHost) && isLiteralLocal(host)) return;',
        'if (false && isLiteralLocal(rawHost) && isLiteralLocal(host)) return;',
      );
    },
  },
  {
    name: 'DEPS-MALICIOUS-001',
    file: join(root, 'src', 'modules', 'deps', 'index.ts'),
    apply: (src) => {
      if (!src.includes('isMaliciousAdvisory(vuln)')) {
        throw new Error('DEPS-MALICIOUS-001 site missing');
      }
      return src.replaceAll('isMaliciousAdvisory(vuln)', 'false && isMaliciousAdvisory(vuln)');
    },
  },
  {
    name: 'LLM-001',
    file: join(root, 'src', 'llm', 'index.ts'),
    apply: (src) => {
      if (!src.includes("'LLM-001'")) {
        throw new Error('LLM-001 site missing');
      }
      return src.replaceAll("'LLM-001'", "'LLM-DISABLED'");
    },
  },
  {
    name: 'CONFIG-TRUSTPROXY-001',
    file: join(root, 'src', 'modules', 'config', 'astChecks.ts'),
    apply: (src) => {
      const site = 'if (trustProxyTrue && ipRateLimit) {';
      if (!src.includes(site)) {
        throw new Error('CONFIG-TRUSTPROXY-001 site missing');
      }
      return src.replace(site, 'if (false && trustProxyTrue && ipRateLimit) {');
    },
  },
  {
    name: 'DEPS-PHANTOM-001',
    file: join(root, 'src', 'modules', 'deps', 'phantom.ts'),
    apply: (src) => {
      if (!src.includes("ruleId: 'DEPS-PHANTOM-001'")) {
        throw new Error('DEPS-PHANTOM-001 site missing');
      }
      return src.replace("ruleId: 'DEPS-PHANTOM-001'", "ruleId: 'DEPS-PHANTOM-OFF'");
    },
  },
  {
    name: 'DEPS-LOCKMISMATCH-001',
    file: join(root, 'src', 'modules', 'deps', 'phantom.ts'),
    apply: (src) => {
      if (!src.includes("ruleId: 'DEPS-LOCKMISMATCH-001'")) {
        throw new Error('DEPS-LOCKMISMATCH-001 site missing');
      }
      return src.replace("ruleId: 'DEPS-LOCKMISMATCH-001'", "ruleId: 'DEPS-LOCKMISMATCH-OFF'");
    },
  },
  {
    name: 'SUPPLY-CAP-001',
    file: join(root, 'src', 'supply', 'capabilities.ts'),
    apply: (src) => {
      if (!src.includes("ruleId: 'SUPPLY-CAP-001'")) {
        throw new Error('SUPPLY-CAP-001 site missing');
      }
      return src.replace("ruleId: 'SUPPLY-CAP-001'", "ruleId: 'SUPPLY-CAP-OFF'");
    },
  },
  {
    name: 'MCP-001',
    file: join(root, 'src', 'modules', 'mcp', 'index.ts'),
    apply: (src) => {
      if (!src.includes("'MCP-001'")) {
        throw new Error('MCP-001 site missing');
      }
      return src.replaceAll("'MCP-001'", "'MCP-DISABLED'");
    },
  },
];

for (const extra of EXTRA_TARGETS) {
  const rel = relative(root, extra.file);
  const original = readFileSync(extra.file, 'utf8');
  const mutated = extra.apply(original);
  console.log(`mutation-smoke: disabling ${extra.name} in ${rel} ...`);
  writeFileSync(extra.file, mutated);
  let result;
  try {
    result = runSuite();
  } finally {
    writeFileSync(extra.file, original);
  }
  if (result.status === 0) {
    fakeTested.push(extra.name);
    console.error(`  ✖ suite still passes with ${extra.name} disabled — its tests are fake`);
  } else {
    console.log(`  ✔ suite fails (${result.stage}) when ${extra.name} is disabled`);
  }
}

spawnSync(isWindows ? 'npm.cmd' : 'npm', ['run', 'build'], {
  cwd: root,
  stdio: 'ignore',
  shell: isWindows,
});

if (fakeTested.length > 0) {
  console.error(`mutation-smoke FAILED: ${fakeTested.join(', ')}`);
  process.exit(1);
}
console.log(`mutation-smoke: ${ruleFiles.length} rule(s) + ${EXTRA_TARGETS.length} extra target(s) verified.`);
