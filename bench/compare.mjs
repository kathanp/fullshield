#!/usr/bin/env node
/**
 * Competitive comparison on tuning apps only.
 * Does not invent results. If a tool is missing, it is reported as not run.
 *
 *   node bench/compare.mjs
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
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

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const out = join(root, 'COMPARISON.md');
  writeFileSync(out, `${lines.join('\n')}\n`);
  console.log(`wrote ${out}`);
}
