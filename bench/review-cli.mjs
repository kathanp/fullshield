#!/usr/bin/env node
/**
 * Phase 67 review CLI, precision session (Phase 76).
 * Shows the ±5 line snippet and the trace. The human types tp, fp, or unsure.
 * Refuses a non-TTY, CI, and agent environments. Does not scan.
 *
 *   node bench/review-cli.mjs --app <name> --precision
 */
import { createInterface } from 'node:readline';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/** Text the human sees for one unlabeled precision row. */
export function precisionReviewText(row) {
  const steps = Array.isArray(row.trace) ? row.trace : [];
  const trace = steps
    .map((step) => `${step.file ?? ''}:${step.line ?? ''} ${step.note ?? ''}`.trim())
    .join('\n');
  return [
    `${row.ruleId ?? ''} ${row.file ?? ''}:${row.line ?? ''}`,
    'snippet (±5 lines):',
    row.snippet ?? '',
    'trace:',
    trace,
    'label: tp / fp / unsure (s skip, q quit)',
  ].join('\n');
}

/** Empty string when the review CLI may talk to a human. */
export function reviewBlocked(env, isTTY) {
  if (env.CI !== undefined && env.CI !== '') return 'review CLI refuses to run when CI is set';
  const agent = env.CURSOR_AGENT !== undefined && env.CURSOR_AGENT !== '';
  const fullshieldAgent = env.FULLSHIELD_AGENT !== undefined && env.FULLSHIELD_AGENT !== '';
  if (agent || fullshieldAgent) return 'review CLI refuses to run when an agent env is set';
  if (!isTTY) return 'review CLI refuses to run when stdin is not a TTY';
  return '';
}

function arg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return undefined;
  const value = process.argv[idx + 1];
  if (value === undefined || value.startsWith('--')) return undefined;
  return value;
}

function ask(rl, prompt) {
  return new Promise((resolve) => {
    rl.question(`${prompt}\n> `, resolve);
  });
}

async function labelRows(doc, rl) {
  const reviewer = String(await ask(rl, 'reviewer name')).trim();
  if (reviewer === '') {
    console.error('reviewer name is required');
    return false;
  }
  for (const row of doc.rows ?? []) {
    if (row.label !== null && row.label !== undefined) continue;
    let pending = true;
    while (pending) {
      const answer = String(await ask(rl, precisionReviewText(row))).trim().toLowerCase();
      if (answer === 'q') return true;
      if (answer === 's') {
        pending = false;
        continue;
      }
      if (answer === 'tp' || answer === 'fp' || answer === 'unsure') {
        const note = String(await ask(rl, 'note (empty leaves null)')).trim();
        row.label = answer;
        row.reviewer = reviewer;
        row.note = note.length === 0 ? null : note;
        pending = false;
        continue;
      }
      console.log('enter tp, fp, unsure, s, or q');
    }
  }
  return true;
}

async function main() {
  const blocked = reviewBlocked(process.env, Boolean(process.stdin.isTTY));
  if (blocked !== '') {
    console.error(blocked);
    process.exit(1);
  }
  if (!process.argv.includes('--precision')) {
    console.error('usage: node bench/review-cli.mjs --app <name> --precision');
    process.exit(2);
  }
  const app = arg('--app');
  if (app === undefined) {
    console.error('pass --app');
    process.exit(2);
  }
  const file = join(root, 'bench', 'precision', `${app}.todo.json`);
  if (!existsSync(file)) {
    console.error(`no precision todo for ${app}. Run scripts/precision-sample.mjs first.`);
    process.exit(1);
  }
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const wrote = await labelRows(doc, rl);
  rl.close();
  if (!wrote) process.exit(1);
  writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
