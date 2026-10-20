#!/usr/bin/env node
/**
 * Mutation smoke test (SECURITY_SCANNER_SPEC.md §0.1 step 5).
 *
 * Copies src/ to os.tmpdir, disables one detection site in that copy, and runs
 * the suite against the copy. This script never writes under the repo's src/.
 * (D14: the previous version rewrote src/ in place, and an interrupted run
 * left `void(` mutants behind.)
 */
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { assertSrcTestClean } from './verify-lock.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const RULE_DIRS = [join('src', 'modules', 'sast', 'rules'), join('src', 'modules', 'secrets', 'rules')];
const REPORT_CALL = 'ctx.report(';
const DISABLED_CALL = 'void(';
const overlayConfig = join(root, '.fullshield-mutation.vitest.config.ts');

let tempRoot;
let distBackup;

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

function tempFile(repoFile) {
  return join(tempRoot, relative(root, repoFile));
}

function prepareSandbox() {
  tempRoot = mkdtempSync(join(tmpdir(), 'fullshield-mut-'));
  cpSync(join(root, 'src'), join(tempRoot, 'src'), { recursive: true });
  cpSync(join(root, 'package.json'), join(tempRoot, 'package.json'));
  cpSync(join(root, 'tsconfig.json'), join(tempRoot, 'tsconfig.json'));
  cpSync(join(root, 'tsup.config.ts'), join(tempRoot, 'tsup.config.ts'));
  symlinkSync(join(root, 'node_modules'), join(tempRoot, 'node_modules'), 'dir');
}

function installDist(staging) {
  const dest = join(root, 'dist');
  const backup = join(root, '.fullshield-dist-backup');
  if (existsSync(backup)) rmSync(backup, { recursive: true, force: true });
  if (existsSync(dest)) renameSync(dest, backup);
  try {
    renameSync(staging, dest);
  } catch {
    cpSync(staging, dest, { recursive: true });
  }
  distBackup = existsSync(backup) ? backup : undefined;
}

function cleanup() {
  const dest = join(root, 'dist');
  if (distBackup !== undefined && existsSync(distBackup)) {
    if (existsSync(dest)) rmSync(dest, { recursive: true, force: true });
    renameSync(distBackup, dest);
    distBackup = undefined;
  }
  if (existsSync(overlayConfig)) rmSync(overlayConfig, { force: true });
  if (tempRoot !== undefined && existsSync(tempRoot)) rmSync(tempRoot, { recursive: true, force: true });
}

process.on('SIGTERM', () => {
  cleanup();
  process.exit(1);
});
process.on('SIGINT', () => {
  cleanup();
  process.exit(1);
});

function writeOverlay() {
  const repoSrc = join(root, 'src');
  const tempSrc = join(tempRoot, 'src');
  writeFileSync(overlayConfig, `import { existsSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { mergeConfig } from 'vitest/config';
import base from ${JSON.stringify(join(root, 'vitest.config.ts'))};

const repoSrc = ${JSON.stringify(repoSrc)};
const tempSrc = ${JSON.stringify(tempSrc)};

function redirect(source, importer) {
  if (importer === undefined) return null;
  let abs = null;
  if (source.startsWith('.')) abs = resolve(dirname(importer), source);
  else if (source.startsWith(repoSrc)) abs = source;
  if (abs === null) return null;
  const rel = relative(repoSrc, abs);
  if (rel.startsWith('..') || rel === '') return null;
  const mapped = resolve(tempSrc, rel);
  const stem = mapped.replace(/\\.(js|ts|tsx|mjs|cjs)$/, '');
  const candidates = [mapped, stem + '.ts', stem + '.tsx', stem + '.js', mapped + '.ts'];
  return candidates.find((file) => existsSync(file)) ?? null;
}

export default mergeConfig(base, {
  plugins: [{
    name: 'fullshield-mutation-src',
    enforce: 'pre',
    resolveId(source, importer) {
      return redirect(source, importer);
    },
  }],
});
`);
}

function runSuite() {
  const tsup = join(root, 'node_modules', 'tsup', 'dist', 'cli-default.js');
  const built = spawnSync(process.execPath, [tsup], { cwd: tempRoot, encoding: 'utf8' });
  if (built.status !== 0) return { status: built.status ?? 1, stage: 'build' };
  const staging = join(tempRoot, 'dist');
  if (!existsSync(staging)) return { status: 1, stage: 'build' };
  installDist(staging);
  writeOverlay();
  const vitest = join(root, 'node_modules', 'vitest', 'vitest.mjs');
  const test = spawnSync(process.execPath, [vitest, 'run', '--config', overlayConfig], {
    cwd: root,
    encoding: 'utf8',
  });
  return { status: test.status ?? 1, stage: 'test' };
}

function withMutant(repoFile, nextText) {
  const dest = tempFile(repoFile);
  const original = readFileSync(dest, 'utf8');
  writeFileSync(dest, nextText);
  let result;
  try {
    result = runSuite();
  } finally {
    writeFileSync(dest, original);
  }
  return result;
}

const EXTRA_TARGETS = [
  {
    name: 'EDGE-*',
    file: join(root, 'src', 'modules', 'edge', 'index.ts'),
    apply: (src) => {
      if (!src.includes('findings.push(')) throw new Error('EDGE findings.push site missing');
      return src.replaceAll('findings.push(', 'void (');
    },
  },
  {
    name: 'AI-INJECT-001',
    file: join(root, 'src', 'ai', 'injection.ts'),
    apply: (src) => {
      if (!src.includes('findings.push(')) throw new Error('AI-INJECT-001 findings.push site missing');
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
      return src.replace('const findings: Finding[] = [noLockFinding()];', 'const findings: Finding[] = [];');
    },
  },
  {
    name: 'interproc taint',
    file: join(root, 'src', 'modules', 'sast', 'interproc.ts'),
    apply: (src) => {
      if (!src.includes('args.findings.push(')) throw new Error('interproc pushSinkFinding site missing');
      return src.replaceAll('args.findings.push(', 'void (');
    },
  },
  {
    name: 'RASP structure-change',
    file: join(root, 'src', 'runtime', 'rasp', 'decide.ts'),
    apply: (src) => {
      if (!src.includes('const hit = detectStructureChange')) throw new Error('RASP decideSink site missing');
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
      if (!src.includes('if (hasChain && hasNet)')) throw new Error('SUPPLY-CHAINC2-001 site missing');
      return src.replace('if (hasChain && hasNet)', 'if (false && hasChain && hasNet)');
    },
  },
  {
    name: 'SUPPLY-NPMRC-NET-001',
    file: join(root, 'src', 'supply', 'index.ts'),
    apply: (src) => {
      if (!src.includes('if (readsNpmrc && hasNet)')) throw new Error('SUPPLY-NPMRC-NET-001 site missing');
      return src.replace('if (readsNpmrc && hasNet)', 'if (false && readsNpmrc && hasNet)');
    },
  },
  {
    name: 'confirm scope lock',
    file: join(root, 'src', 'confirm', 'index.ts'),
    apply: (src) => {
      if (!src.includes('if (isLiteralLocal(rawHost) && isLiteralLocal(host)) {return;}')) {
        throw new Error('confirm scope lock site missing');
      }
      return src.replace(
        'if (isLiteralLocal(rawHost) && isLiteralLocal(host)) {return;}',
        'if (false && isLiteralLocal(rawHost) && isLiteralLocal(host)) {return;}',
      );
    },
  },
  {
    name: 'DEPS-MALICIOUS-001',
    file: join(root, 'src', 'modules', 'deps', 'index.ts'),
    apply: (src) => {
      if (!src.includes('isMaliciousAdvisory(vuln)')) throw new Error('DEPS-MALICIOUS-001 site missing');
      return src.replaceAll('isMaliciousAdvisory(vuln)', 'false && isMaliciousAdvisory(vuln)');
    },
  },
  {
    name: 'LLM-001',
    file: join(root, 'src', 'llm', 'index.ts'),
    apply: (src) => {
      if (!src.includes("'LLM-001'")) throw new Error('LLM-001 site missing');
      return src.replaceAll("'LLM-001'", "'LLM-DISABLED'");
    },
  },
  {
    name: 'CONFIG-TRUSTPROXY-001',
    file: join(root, 'src', 'modules', 'config', 'astChecks.ts'),
    apply: (src) => {
      const site = 'if (trustProxyTrue && ipRateLimit) {';
      if (!src.includes(site)) throw new Error('CONFIG-TRUSTPROXY-001 site missing');
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
    name: 'MCP-001',
    file: join(root, 'src', 'modules', 'mcp', 'index.ts'),
    apply: (src) => {
      if (!src.includes("'MCP-001'")) throw new Error('MCP-001 site missing');
      return src.replaceAll("'MCP-001'", "'MCP-DISABLED'");
    },
  },
];

prepareSandbox();

if (process.env.FULLSHIELD_MUTATION_HOLD === '1') {
  const target = collectRuleFiles().find((file) => readFileSync(tempFile(file), 'utf8').includes(REPORT_CALL));
  if (target !== undefined) {
    const dest = tempFile(target);
    writeFileSync(dest, readFileSync(dest, 'utf8').replaceAll(REPORT_CALL, DISABLED_CALL));
  }
  console.log('mutation-smoke: holding');
  setInterval(() => {}, 60_000);
} else {
runMutations();
}

function runMutations() {

const ruleFiles = collectRuleFiles();
if (ruleFiles.length === 0) {
  console.log('mutation-smoke: no SAST/secrets rule files exist yet (expected before Phase 2); nothing to mutate.');
  cleanup();
  assertSrcTestClean(root, 'mutation-smoke');
  process.exit(0);
}

const fakeTested = [];
for (const file of ruleFiles) {
  const rel = relative(root, file);
  const original = readFileSync(tempFile(file), 'utf8');
  if (!original.includes(REPORT_CALL)) {
    console.error(`mutation-smoke: ${rel} does not call ctx.report( — it violates the rule convention and cannot be mutation-tested.`);
    cleanup();
    process.exit(1);
  }
  console.log(`mutation-smoke: disabling detection in ${rel} ...`);
  const result = withMutant(file, original.replaceAll(REPORT_CALL, DISABLED_CALL));
  if (result.status === 0) {
    fakeTested.push(rel);
    console.error(`  ✖ suite still passes with ${rel} disabled — its tests are fake`);
  } else {
    console.log(`  ✔ suite fails (${result.stage}) when ${rel} is disabled`);
  }
}

for (const extra of EXTRA_TARGETS) {
  const rel = relative(root, extra.file);
  const original = readFileSync(tempFile(extra.file), 'utf8');
  console.log(`mutation-smoke: disabling ${extra.name} in ${rel} ...`);
  const result = withMutant(extra.file, extra.apply(original));
  if (result.status === 0) {
    fakeTested.push(extra.name);
    console.error(`  ✖ suite still passes with ${extra.name} disabled — its tests are fake`);
  } else {
    console.log(`  ✔ suite fails (${result.stage}) when ${extra.name} is disabled`);
  }
}

cleanup();
assertSrcTestClean(root, 'mutation-smoke');
if (fakeTested.length > 0) {
  console.error(`mutation-smoke FAILED: ${fakeTested.join(', ')}`);
  process.exit(1);
}
console.log(`mutation-smoke: ${ruleFiles.length} rule(s) + ${EXTRA_TARGETS.length} extra target(s) verified.`);
}
