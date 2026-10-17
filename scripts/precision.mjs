#!/usr/bin/env node
/**
 * Precision from human-labeled review CSVs.
 * Blank labels are ignored. "unsure" is counted separately and is not a true positive.
 *
 *   node scripts/precision.mjs
 *   node scripts/precision.mjs bench/review
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const ALLOWED = new Set(['TP', 'FP', 'unsure', '']);

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else quoted = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"') {
      quoted = true;
      continue;
    }
    if (ch === ',') {
      row.push(cell);
      cell = '';
      continue;
    }
    if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1;
      row.push(cell);
      if (row.some((value) => value.length > 0)) rows.push(row);
      row = [];
      cell = '';
      continue;
    }
    cell += ch;
  }
  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    if (row.some((value) => value.length > 0)) rows.push(row);
  }
  if (rows.length === 0) return [];
  const header = rows[0].map((name) => name.trim());
  return rows.slice(1).map((values) => {
    const record = {};
    header.forEach((name, index) => {
      record[name] = values[index] ?? '';
    });
    return record;
  });
}

function moduleOf(ruleId) {
  if (ruleId.startsWith('DEPS-')) return 'deps';
  if (ruleId.startsWith('SAST-')) return 'sast';
  if (ruleId.startsWith('SECRET-')) return 'secrets';
  if (ruleId.startsWith('CONFIG-')) return 'config';
  return 'other';
}

export function precisionFromRows(records) {
  const buckets = new Map();
  const bump = (key, label) => {
    const slot = buckets.get(key) ?? { TP: 0, FP: 0, unsure: 0 };
    slot[label] += 1;
    buckets.set(key, slot);
  };
  let ignored = 0;
  for (const record of records) {
    const label = (record.label ?? '').trim();
    if (!ALLOWED.has(label)) {
      throw new Error(`label must be TP, FP, unsure, or blank (got ${JSON.stringify(label)})`);
    }
    if (label === '') {
      ignored += 1;
      continue;
    }
    const ruleId = record.ruleId ?? '';
    bump(`module\t${moduleOf(ruleId)}`, label);
    bump(`rule\t${ruleId}`, label);
  }
  return { buckets, ignored };
}

function ratio(slot) {
  const decided = slot.TP + slot.FP;
  if (decided === 0) return 'n/a';
  return (slot.TP / decided).toFixed(3);
}

function printGroup(title, buckets, prefix) {
  console.log(title);
  const rows = [...buckets.entries()].filter(([key]) => key.startsWith(prefix));
  rows.sort((a, b) => a[0].localeCompare(b[0]));
  for (const [key, slot] of rows) {
    const name = key.slice(prefix.length);
    console.log(
      `${name}\tTP=${slot.TP}\tFP=${slot.FP}\tunsure=${slot.unsure}\tprecision=${ratio(slot)} (unsure excluded)`,
    );
  }
}

function main() {
  const dir = process.argv[2] ?? join(root, 'bench', 'review');
  if (!existsSync(dir)) {
    console.log(`no review directory at ${dir}`);
    console.log('precision is not sampled. Blank labels are not counts.');
    return;
  }
  const files = readdirSync(dir).filter((name) => name.endsWith('.csv'));
  if (files.length === 0) {
    console.log('no labeled CSVs. precision is not sampled.');
    return;
  }
  const records = [];
  for (const name of files) {
    records.push(...parseCsv(readFileSync(join(dir, name), 'utf8')));
  }
  const { buckets, ignored } = precisionFromRows(records);
  console.log('Not reviewed until a human fills label. This is not a recall claim.');
  console.log(`blank labels ignored: ${ignored}`);
  printGroup('module', buckets, 'module\t');
  printGroup('rule', buckets, 'rule\t');
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
