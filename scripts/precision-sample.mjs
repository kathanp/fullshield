#!/usr/bin/env node
/**
 * Deterministic per-rule sample for a human precision review.
 * label, reviewer, and note are always null. Do not fill them here.
 *
 *   node scripts/precision-sample.mjs --app <name> --per-rule 10 --seed <n>
 *   node scripts/precision-sample.mjs --app <name> --per-rule 10 --seed <n> --from scan.json --checkout <dir> --out <file>
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { mulberry32 } from './sample-findings.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const CHECKOUT_DIRS = {
  nodegoat: ['NodeGoat', 'nodegoat'],
  'juice-shop': ['juice-shop'],
  dvna: ['dvna'],
  goof: ['goof', 'nodejs-goof'],
  'vulnerable-node': ['vulnerable-node'],
};

function arg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return undefined;
  const value = process.argv[idx + 1];
  if (value === undefined || value.startsWith('--')) return undefined;
  return value;
}

function integerArg(name, fallback) {
  const raw = arg(name);
  if (raw === undefined) {
    if (fallback !== undefined) return fallback;
    console.error(`pass ${name}`);
    process.exit(2);
  }
  if (!/^-?\d+$/.test(raw)) {
    console.error(`${name} must be an integer`);
    process.exit(2);
  }
  return Number(raw);
}

function stableCompare(a, b) {
  const fileA = String(a.file ?? '');
  const fileB = String(b.file ?? '');
  if (fileA < fileB) return -1;
  if (fileA > fileB) return 1;
  const lineA = Number(a.line ?? 0);
  const lineB = Number(b.line ?? 0);
  if (lineA !== lineB) return lineA - lineB;
  const idA = String(a.id ?? '');
  const idB = String(b.id ?? '');
  if (idA < idB) return -1;
  if (idA > idB) return 1;
  return 0;
}

function shuffle(list, random) {
  const copy = [...list];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    const swap = copy[i];
    copy[i] = copy[j];
    copy[j] = swap;
  }
  return copy;
}

/** Up to `perRule` findings for each rule id. Same seed and same set → same rows. */
export function samplePerRule(findings, perRule, seed) {
  const limit = Number(perRule);
  const random = mulberry32(Number(seed) >>> 0);
  const groups = new Map();
  for (const finding of findings) {
    const ruleId = finding.ruleId;
    if (typeof ruleId !== 'string' || ruleId.length === 0) continue;
    const list = groups.get(ruleId) ?? [];
    list.push(finding);
    groups.set(ruleId, list);
  }
  const picked = [];
  for (const ruleId of [...groups.keys()].sort()) {
    const ordered = [...(groups.get(ruleId) ?? [])].sort(stableCompare);
    const shuffled = shuffle(ordered, random);
    const take = limit < 1 ? 0 : Math.min(limit, shuffled.length);
    picked.push(...shuffled.slice(0, take));
  }
  return picked;
}

function snippetAround(checkout, file, line) {
  if (checkout === undefined || file === undefined || file === '') return '';
  const full = join(checkout, file);
  if (!existsSync(full)) return '';
  let text = '';
  try {
    text = readFileSync(full, 'utf8');
  } catch {
    return '';
  }
  if (text.includes('\u0000')) return '';
  const rows = text.split(/\r?\n/);
  const at = Number(line);
  if (!Number.isInteger(at) || at < 1) return '';
  const start = Math.max(0, at - 1 - 5);
  const end = Math.min(rows.length, at + 5);
  return rows.slice(start, end).join('\n');
}

function todoRow(finding, checkout) {
  const trace = Array.isArray(finding.trace)
    ? finding.trace.map((step) => ({
        file: step.file,
        line: step.line,
        note: step.note,
      }))
    : [];
  return {
    id: finding.id ?? '',
    ruleId: finding.ruleId,
    file: finding.file ?? '',
    line: finding.line ?? null,
    severity: finding.severity ?? '',
    message: finding.message ?? '',
    snippet: snippetAround(checkout, finding.file, finding.line),
    trace,
    label: null,
    reviewer: null,
    note: null,
  };
}

function loadApp(name) {
  const holdouts = JSON.parse(readFileSync(join(root, 'bench', 'holdouts.json'), 'utf8'));
  const meta = (holdouts.apps ?? []).find((item) => item.name === name);
  if (meta === undefined) {
    console.error(`unknown app ${name}`);
    process.exit(2);
  }
  if (meta.status !== 'tuning' && meta.status !== 'seen') {
    console.error(`${name} is untouched. Precision sampling does not scan it.`);
    process.exit(1);
  }
  return meta;
}

function findCheckout(name) {
  const home = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');
  const names = CHECKOUT_DIRS[name] ?? [name];
  for (const dir of names) {
    const full = join(home, dir);
    if (existsSync(join(full, 'package.json'))) return full;
  }
  return undefined;
}

function parseScanJson(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('scan json missing');
  return JSON.parse(text.slice(start, end + 1));
}

function defaultScan(dir) {
  const cli = join(root, 'dist', 'cli', 'index.js');
  if (!existsSync(cli)) throw new Error('dist/cli/index.js missing. Build before sampling a checkout.');
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith('FULLSHIELD_EXPERIMENTAL_')) continue;
    if (key === 'FULLSHIELD_TAINT_SUMMARIES') continue;
    if (value !== undefined) env[key] = value;
  }
  const result = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    env,
  });
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(`scan exited ${result.status} ${(result.stderr ?? '').slice(0, 500)}`);
  }
  return parseScanJson(result.stdout ?? '');
}

function findingsFrom(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (Array.isArray(parsed)) return parsed;
  return parsed.findings ?? [];
}

function main() {
  const app = arg('--app');
  if (app === undefined || app === '') {
    console.error('pass --app');
    process.exit(2);
  }
  const perRule = integerArg('--per-rule', 10);
  const seed = integerArg('--seed');
  loadApp(app);
  const from = arg('--from');
  const checkout = arg('--checkout') ?? findCheckout(app);
  let findings = [];
  if (from !== undefined) {
    findings = findingsFrom(from);
  } else if (checkout === undefined) {
    console.error(`no checkout for ${app}. Precision sampling does not invent findings.`);
    process.exit(1);
  } else {
    findings = defaultScan(checkout).findings ?? [];
  }
  const rows = samplePerRule(findings, perRule, seed).map((finding) => todoRow(finding, checkout));
  const out = arg('--out') ?? join(root, 'bench', 'precision', `${app}.todo.json`);
  mkdirSync(dirname(out), { recursive: true });
  const doc = { app, seed, perRule, rows };
  writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${rows.length} rows to ${out}. label, reviewer, and note are null.`);
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
