#!/usr/bin/env node
/**
 * Phase 93 promotion evidence (process only).
 * Writes one markdown file per batch flag plus SUMMARY.md.
 * Does not scan apps, does not invent counts, and never marks a flag stable.
 */
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const BATCH = [
  'FULLSHIELD_EXPERIMENTAL_VALIDATION',
  'FULLSHIELD_EXPERIMENTAL_WORKSPACES',
  'FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH',
  'FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES',
  'FULLSHIELD_EXPERIMENTAL_ROUTES',
  'FULLSHIELD_EXPERIMENTAL_EXPLAIN',
  'FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE',
  'FULLSHIELD_EXPERIMENTAL_DEPS_DIFF',
  'FULLSHIELD_EXPERIMENTAL_LOCKFILES',
  'FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS',
  'FULLSHIELD_EXPERIMENTAL_SBOM_REACH',
  'FULLSHIELD_EXPERIMENTAL_SARIF_V2',
  'FULLSHIELD_EXPERIMENTAL_PERF2',
  'FULLSHIELD_EXPERIMENTAL_BUDGET',
  'FULLSHIELD_EXPERIMENTAL_TYPES',
  'FULLSHIELD_EXPERIMENTAL_MODELS',
  'FULLSHIELD_EXPERIMENTAL_SECRET_CHECK',
  'FULLSHIELD_EXPERIMENTAL_INGEST',
  'FULLSHIELD_EXPERIMENTAL_PRIORITY',
  'FULLSHIELD_EXPERIMENTAL_PATHS',
  'FULLSHIELD_EXPERIMENTAL_CAPABILITIES',
  'FULLSHIELD_EXPERIMENTAL_PROVENANCE',
  'FULLSHIELD_EXPERIMENTAL_DEV',
  'FULLSHIELD_EXPERIMENTAL_SPDX',
  'FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES',
  'FULLSHIELD_EXPERIMENTAL_FIX_VERIFY',
];

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return undefined;
  return process.argv[index + 1];
}

function refuseStable() {
  if (process.argv.includes('--promote') || process.argv.includes('--promoted')) {
    process.stderr.write('refusing to mark a flag stable\n');
    process.exit(1);
  }
}

function visibleFlags(root) {
  const found = new Set();
  const src = join(root, 'src');
  let names;
  try {
    names = readdirSync(src, { recursive: true });
  } catch {
    return found;
  }
  for (const name of names) {
    const path = join(src, String(name));
    if (!/\.(ts|tsx|js|mjs|cjs)$/.test(path)) continue;
    let text;
    try {
      text = readFileSync(path, 'utf8');
    } catch {
      continue;
    }
    for (const match of text.matchAll(/FULLSHIELD_EXPERIMENTAL_[A-Z0-9_]+/g)) {
      found.add(match[0]);
    }
  }
  return found;
}

function flagPage(flag, present) {
  const absent = 'unmet / not in this tree';
  const diff = present ? 'not scanned' : absent;
  const crashes = present ? 'not scanned' : absent;
  const unmet = present
    ? 'unmet (no stored scan); unmet — needs Phase 68 run after review; unmet (no human approval)'
    : absent;
  return [
    `# \`${flag}\``,
    '',
    'Phase 93 evidence. This file does not move the flag to stable.',
    '',
    '| column | value |',
    '|---|---|',
    `| tuning-app key diff (flag on vs off, labeled seen) | ${diff} |`,
    `| crash count on the bench/realworld.json corpus | ${crashes} |`,
    '| default-scan-diff if promoted | EMPTY |',
    `| criteria not met | ${unmet} |`,
    '',
  ].join('\n');
}

function summaryPage(rows) {
  const lines = [
    '# Promotion evidence batch 2',
    '',
    'Process only. No flag is moved to stable.',
    '',
    '| flag | criteria met | criteria unmet | default-scan-diff if promoted |',
    '|---|---|---|---|',
  ];
  for (const row of rows) {
    lines.push(`| \`${row.flag}\` | ${row.met} | ${row.unmet} | EMPTY |`);
  }
  lines.push('');
  return lines.join('\n');
}

function main() {
  refuseStable();
  const root = argValue('--root') ?? repoRoot;
  const out = argValue('--out') ?? join(root, 'bench', 'promotion');
  const visible = visibleFlags(root);
  const rows = BATCH.map((flag) => {
    const present = visible.has(flag);
    return {
      flag,
      present,
      met: 'none',
      unmet: present ? 'unmet (no stored scan)' : 'unmet / not in this tree',
    };
  });
  mkdirSync(out, { recursive: true });
  for (const row of rows) {
    writeFileSync(join(out, `${row.flag}.md`), `${flagPage(row.flag, row.present)}\n`);
  }
  const summary = summaryPage(rows);
  if (/\|\s*promoted\s*\|/i.test(summary)) {
    process.stderr.write('refusing to mark a flag stable\n');
    process.exit(1);
  }
  writeFileSync(join(out, 'SUMMARY.md'), summary);
}

main();
