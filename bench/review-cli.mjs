#!/usr/bin/env node
/**
 * Phase 67. Human review only. Refuses CI, agents, and a non-TTY.
 * Tests inject lines and forceTty. This file is not part of the npm package.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

export function refused(env = process.env, tty = process.stdin.isTTY === true) {
  if (env.CI) return 'review-cli refuses to run when CI is set';
  if (env.CURSOR_AGENT || env.FULLSHIELD_AGENT) return 'review-cli refuses to run under an agent';
  if (!tty) return 'review-cli refuses to run when stdin is not a TTY';
  return undefined;
}

function gitName() {
  const result = spawnSync('git', ['config', 'user.name'], { encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : '';
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function excerpt(root, file, line) {
  try {
    const lines = readFileSync(join(root, file), 'utf8').split(/\r?\n/);
    const at = Math.max(0, line - 1);
    return lines.slice(at, at + 5).join('\n');
  } catch {
    return '';
  }
}

function parseCsv(text) {
  const [header, ...rows] = text.split(/\r?\n/).filter((line) => line.length > 0);
  const cols = header.split(',');
  return rows.map((row) => {
    const cells = row.split(',');
    const rec = {};
    cols.forEach((col, i) => {
      rec[col.trim()] = cells[i] ?? '';
    });
    return rec;
  });
}

function toCsv(rows) {
  const cols = ['id', 'ruleId', 'severity', 'file', 'line', 'snippet', 'message', 'label', 'reviewer', 'note'];
  const lines = [cols.join(',')];
  for (const row of rows) lines.push(cols.map((col) => String(row[col] ?? '').replaceAll(',', ' ')).join(','));
  return `${lines.join('\n')}\n`;
}

/**
 * @param {{ root: string, app: string, mode: 'ground-truth' | 'findings', lines: string[], env?: NodeJS.ProcessEnv, tty?: boolean, reviewerDefault?: string }} opts
 */
export function runReview(opts) {
  const env = opts.env ?? process.env;
  const why = refused(env, opts.tty !== false);
  if (why) {
    const error = new Error(why);
    error.code = 'REFUSED';
    throw error;
  }
  const lines = [...opts.lines];
  const take = () => (lines.length > 0 ? lines.shift() : 'q');
  const appDir = join(opts.root, opts.app);
  const reviewer = opts.reviewerDefault ?? take() ?? gitName();
  if (opts.mode === 'findings') {
    const csvPath = join(opts.root, 'review', `${opts.app}.csv`);
    const rows = parseCsv(readFileSync(csvPath, 'utf8'));
    for (const row of rows) {
      if (row.label) continue;
      const choice = take();
      if (choice === 'q') break;
      if (choice !== 'TP' && choice !== 'FP' && choice !== 'unsure') continue;
      row.label = choice;
      row.reviewer = reviewer;
      row.note = take() ?? '';
    }
    writeFileSync(csvPath, toCsv(rows));
    return { reviewer, wrote: csvPath };
  }
  const gtPath = join(appDir, 'ground-truth.json');
  const gt = readJson(gtPath);
  const logPath = join(appDir, 'review-log.json');
  const log = existsSync(logPath) ? readJson(logPath) : { reviewer, decisions: [] };
  log.reviewer = log.reviewer || reviewer;
  const decided = new Set(log.decisions.map((row) => `${row.file}:${row.line}`));
  for (const entry of gt.entries) {
    const key = `${entry.file}:${entry.line}`;
    if (decided.has(key)) continue;
    const choice = take();
    if (choice === 'q') break;
    if (choice === 's') continue;
    if (choice === 'y') {
      log.decisions.push({
        file: entry.file,
        line: entry.line,
        decision: 'confirm',
        reason: '',
        reviewer: log.reviewer,
        timestamp: new Date().toISOString(),
        source: entry.source,
        class: entry.class,
        inScope: entry.inScope,
        excerpt: excerpt(appDir, entry.file, entry.line),
      });
      continue;
    }
    if (choice === 'n') {
      const reason = take() ?? '';
      if (reason.trim() === '') throw new Error('reject requires a reason');
      log.decisions.push({
        file: entry.file,
        line: entry.line,
        decision: 'reject',
        reason,
        reviewer: log.reviewer,
        timestamp: new Date().toISOString(),
        source: entry.source,
        class: entry.class,
        inScope: entry.inScope,
        excerpt: excerpt(appDir, entry.file, entry.line),
      });
    }
  }
  writeFileSync(logPath, `${JSON.stringify(log, null, 2)}\n`);
  const covered = new Set(log.decisions.map((row) => `${row.file}:${row.line}`));
  const complete = gt.entries.every((entry) => covered.has(`${entry.file}:${entry.line}`));
  if (complete) {
    const typed = take();
    if (typed === gt.app) {
      gt.reviewed = true;
      writeFileSync(gtPath, `${JSON.stringify(gt, null, 2)}\n`);
    }
  }
  return { reviewer: log.reviewer, wrote: logPath, reviewed: gt.reviewed === true };
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const why = refused();
    if (why) throw new Error(why);
    const app = arg('--app');
    if (!app) throw new Error('review-cli requires --app');
    const mode = process.argv.includes('--findings') ? 'findings' : 'ground-truth';
    const lines = [];
    process.stdin.setEncoding('utf8');
    let buf = '';
    for await (const chunk of process.stdin) {
      buf += chunk;
      if (!process.stdin.isTTY) break;
    }
    lines.push(...buf.split(/\r?\n/).filter((line) => line.length > 0));
    runReview({ root: arg('--root') ?? 'bench', app, mode, lines, tty: true, reviewerDefault: gitName() });
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
