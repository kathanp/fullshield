#!/usr/bin/env node
/**
 * Sample findings for a human precision review.
 * Labels, reviewer, and note are always blank. Do not fill them here.
 *
 *   node scripts/sample-findings.mjs
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const benchHome = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');
const SEED = 20261016;
const LIMIT = 30;

export function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function sampleStratified(findings, limit, random) {
  const groups = new Map();
  for (const finding of findings) {
    const module = finding.module ?? 'other';
    const list = groups.get(module) ?? [];
    list.push(finding);
    groups.set(module, list);
  }
  const names = [...groups.keys()].sort();
  if (names.length === 0 || limit < 1) return [];
  const base = Math.floor(limit / names.length);
  let extra = limit - base * names.length;
  const picked = [];
  for (const name of names) {
    const list = groups.get(name) ?? [];
    const want = Math.min(list.length, base + (extra > 0 ? 1 : 0));
    if (extra > 0 && list.length > base) extra -= 1;
    const copy = [...list];
    for (let i = copy.length - 1; i > 0; i -= 1) {
      const j = Math.floor(random() * (i + 1));
      const swap = copy[i];
      copy[i] = copy[j];
      copy[j] = swap;
    }
    picked.push(...copy.slice(0, want));
  }
  return picked.slice(0, limit);
}

function csvCell(value) {
  const text = value === undefined || value === null ? '' : String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replaceAll('"', '""')}"`;
  return text;
}

function snippetAround(dir, file, line) {
  if (!file) return '';
  const full = join(dir, file);
  if (!existsSync(full)) return '';
  let text;
  try {
    text = readFileSync(full, 'utf8');
  } catch {
    return '';
  }
  if (text.includes('\u0000')) return '';
  const lines = text.split(/\r?\n/);
  const at = Math.max(1, Number(line) || 1);
  const start = Math.max(0, at - 3);
  return lines
    .slice(start, start + 5)
    .map((row) => (row.length > 240 ? `${row.slice(0, 240)}…` : row))
    .join('\n');
}

function parseScanJson(stdout) {
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('scan json missing');
  return JSON.parse(stdout.slice(start, end + 1));
}

function scan(dir) {
  const cli = join(root, 'dist', 'cli', 'index.js');
  const result = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(`scan exited ${result.status} signal ${result.signal}\n${(result.stderr ?? '').slice(0, 500)}`);
  }
  return parseScanJson(result.stdout);
}

function main() {
  const registry = JSON.parse(readFileSync(join(root, 'bench', 'realworld.json'), 'utf8'));
  const outDir = join(root, 'bench', 'review');
  mkdirSync(outDir, { recursive: true });
  const header = ['id', 'ruleId', 'severity', 'file', 'line', 'code snippet (5 lines)', 'message', 'label', 'reviewer', 'note'];
  for (const repo of registry.repos ?? []) {
    const dir = join(benchHome, repo.name);
    const out = join(outDir, `${repo.name}.csv`);
    if (!existsSync(join(dir, 'package.json'))) {
      console.log(`${repo.name}: checkout missing. No CSV rows.`);
      writeFileSync(out, `${header.join(',')}\n`);
      continue;
    }
    let findings = [];
    try {
      findings = scan(dir).findings ?? [];
    } catch (error) {
      console.log(`${repo.name}: scan failed. No labels written. ${error instanceof Error ? error.message.split('\n')[0] : error}`);
      writeFileSync(out, `${header.join(',')}\n`);
      continue;
    }
    const sample = sampleStratified(findings, LIMIT, mulberry32(SEED));
    const lines = [header.join(',')];
    for (const finding of sample) {
      lines.push(
        [
          finding.id,
          finding.ruleId,
          finding.severity,
          finding.file ?? '',
          finding.line ?? '',
          snippetAround(dir, finding.file, finding.line),
          finding.message ?? '',
          '',
          '',
          '',
        ]
          .map(csvCell)
          .join(','),
      );
    }
    writeFileSync(out, `${lines.join('\n')}\n`);
    console.log(`${repo.name}: sampled ${sample.length} of ${findings.length}. Labels left blank.`);
  }
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
