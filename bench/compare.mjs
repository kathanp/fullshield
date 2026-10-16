#!/usr/bin/env node
/**
 * Competitive comparison on tuning apps only.
 * Does not invent results. If a tool is missing, it is reported as not run.
 *
 *   node bench/compare.mjs
 */
import { spawnSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const TOOLS = [
  { name: 'semgrep', args: ['--version'] },
  { name: 'osv-scanner', args: ['--version'] },
  { name: 'npm', args: ['--version'] },
];

/** Class buckets. Anything else from a tool is counted as unmapped, not forced into a class. */
export const CLASS_MAP = [
  { tool: 'semgrep', pattern: 'javascript.lang.security.audit.sqli', class: 'sqli' },
  { tool: 'semgrep', pattern: 'javascript.lang.security.audit.command', class: 'cmdi' },
  { tool: 'semgrep', pattern: 'javascript.lang.security.audit.path', class: 'path' },
  { tool: 'semgrep', pattern: 'javascript.lang.security.audit.xss', class: 'xss' },
  { tool: 'osv-scanner', pattern: 'CVE-', class: 'deps' },
  { tool: 'osv-scanner', pattern: 'GHSA-', class: 'deps' },
  { tool: 'npm-audit', pattern: 'advisory', class: 'deps' },
];

function versionOf(name, args) {
  const result = spawnSync(name, args, { encoding: 'utf8' });
  if (result.error !== undefined || result.status !== 0) return null;
  return `${result.stdout}${result.stderr}`.trim().split('\n')[0] ?? null;
}

const lines = [
  '# Comparison',
  '',
  'Human review of the mapping is required before this file is linked from the README.',
  'Numbers below are only filled when the tool was executed in this environment.',
  '',
  '## Tool versions',
  '',
];
let missing = 0;
for (const tool of TOOLS) {
  const version = versionOf(tool.name, tool.args);
  if (version === null) {
    missing += 1;
    lines.push(`- ${tool.name}: not installed. No findings recorded.`);
  } else {
    lines.push(`- ${tool.name}: \`${version}\` (present, not executed by this invocation)`);
  }
}
lines.push('');
lines.push('## Mapping');
lines.push('');
lines.push('| tool | pattern | class |');
lines.push('|---|---|---|');
for (const row of CLASS_MAP) {
  lines.push(`| ${row.tool} | ${row.pattern} | ${row.class} |`);
}
lines.push('');
lines.push('Unmapped rules are counted separately. They are not assigned a FullShield class.');
lines.push('');
lines.push('## Results');
lines.push('');
lines.push('Not executed. No true-positive, miss, or alert counts are recorded.');
lines.push(`Tools missing: ${missing}.`);
lines.push('');

const TUNING = [
  { id: 'nodegoat', dir: 'NodeGoat' },
  { id: 'juice-shop', dir: 'juice-shop' },
  { id: 'dvna', dir: 'dvna' },
  { id: 'goof', dir: 'goof' },
  { id: 'vulnerable-node', dir: 'vulnerable-node' },
];

function countMapped(tool, text) {
  const mapped = {};
  let unmapped = 0;
  const rows = CLASS_MAP.filter((row) => row.tool === tool);
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    const hit = rows.find((row) => line.includes(row.pattern));
    if (hit === undefined) {
      unmapped += 1;
      continue;
    }
    mapped[hit.class] = (mapped[hit.class] ?? 0) + 1;
  }
  return { mapped, unmapped };
}

function runComparison() {
  const benchHome = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');
  const outLines = [
    '# Comparison',
    '',
    'Human review of the mapping is required before this file is linked from the README.',
    'Counts below are from one local run. They are not a recall claim.',
    '',
    '## Tool versions',
    '',
  ];
  const versions = {};
  for (const tool of TOOLS) versions[tool.name] = versionOf(tool.name, tool.args);
  for (const [name, version] of Object.entries(versions)) {
    outLines.push(version === null ? `- ${name}: not installed. No findings recorded.` : `- ${name}: \`${version}\``);
  }
  outLines.push('', '## Mapping', '', '| tool | pattern | class |', '|---|---|---|');
  for (const row of CLASS_MAP) outLines.push(`| ${row.tool} | ${row.pattern} | ${row.class} |`);
  outLines.push('', 'Unmapped rules are counted separately. They are not assigned a FullShield class.', '', '## Results', '');
  for (const app of TUNING) {
    const dir = join(benchHome, app.dir);
    outLines.push(`### ${app.id}`, '');
    if (!existsSync(dir)) {
      outLines.push('Checkout missing. Not executed.', '');
      continue;
    }
    if (versions.semgrep !== null) {
      const sem = spawnSync('semgrep', ['scan', '--config', 'p/javascript', '--config', 'p/typescript', '--config', 'p/nodejs', '--quiet', '--json', dir], {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      });
      let rules = [];
      try {
        rules = JSON.parse(sem.stdout || '{}').results ?? [];
      } catch {
        rules = [];
      }
      const text = rules.map((row) => String(row.check_id ?? '')).join('\n');
      const { mapped, unmapped } = countMapped('semgrep', text);
      outLines.push(`- semgrep findings: ${rules.length}; unmapped: ${unmapped}; mapped: ${JSON.stringify(mapped)}`);
      if (rules[0]?.check_id !== undefined) outLines.push(`- semgrep example check_id: ${rules[0].check_id}`);
      if (sem.status !== 0 && rules.length === 0) outLines.push(`- semgrep exit ${sem.status}: ${(sem.stderr || '').slice(0, 200)}`);
    } else outLines.push('- semgrep: not installed. Not executed.');
    if (versions['osv-scanner'] !== null) {
      const osv = spawnSync('osv-scanner', ['scan', 'source', '-r', dir, '--format', 'json'], {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      });
      let vulns = null;
      try {
        const doc = JSON.parse(osv.stdout || '');
        vulns = 0;
        const packs = doc.results ?? [];
        for (const pack of packs) {
          for (const item of pack.packages ?? []) vulns += (item.vulnerabilities ?? []).length;
        }
      } catch {
        vulns = null;
      }
      if (vulns === null) {
        const reason = `${osv.stderr || osv.stdout || ''}`.trim().split('\n').at(-1) ?? `exit ${osv.status}`;
        outLines.push(`- osv-scanner: not executed (${reason.slice(0, 180)})`);
      } else outLines.push(`- osv-scanner vulnerability records: ${vulns}`);
    } else outLines.push('- osv-scanner: not installed. Not executed.');
    const audit = spawnSync('npm', ['audit', '--json'], { cwd: dir, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    let advisories = null;
    try {
      const doc = JSON.parse(audit.stdout || '');
      advisories = doc.metadata?.vulnerabilities?.total ?? Object.keys(doc.advisories ?? {}).length;
    } catch {
      advisories = null;
    }
    if (advisories === null) {
      const reason = `${audit.stderr || ''}`.trim().split('\n').at(-1) ?? `exit ${audit.status}`;
      outLines.push(`- npm audit: not executed (${reason.slice(0, 180)})`, '');
    } else outLines.push(`- npm audit total: ${advisories}`, '');
  }
  outLines.push('FullShield default-scan counts for these apps stay in BENCHMARK.md. This file does not retune rules.');
  outLines.push('Commercial scanners were not executed.');
  writeFileSync(join(root, 'COMPARISON.md'), `${outLines.join('\n')}\n`);
  console.log('wrote COMPARISON.md from a local run');
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  if (process.argv.includes('--run')) runComparison();
  else {
    const out = join(root, 'COMPARISON.md');
    writeFileSync(out, `${lines.join('\n')}\n`);
    console.log(`wrote ${out}`);
  }
}
