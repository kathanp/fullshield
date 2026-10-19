#!/usr/bin/env node
/**
 * Phase 68. One-shot holdout scan. Tests inject git and scan.
 * Do not point this at the real holdouts unless the human asked.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const RESERVE = 2;

export function holdoutPlan(input) {
  const tag = `freeze-${input.release}`;
  if (input.headTag !== tag) {
    throw new Error(`holdout-run refuses: HEAD is not tagged ${tag}`);
  }
  const dirty = (input.changedFiles ?? []).filter(
    (file) => file.startsWith('src/modules/') || file.startsWith('rules/'),
  );
  if (dirty.length > 0) {
    throw new Error(`holdout-run refuses: ${dirty[0]} changed since ${tag}`);
  }
  const apps = input.apps.filter((app) => app.status === 'untouched');
  const already = apps.filter((app) => existsSync(join(input.resultsDir, `${app.name}-${input.release}.json`)));
  if (already.length > 0) {
    throw new Error(`holdout-run refuses: ${already[0].name} already has a result for ${input.release}`);
  }
  if (apps.length - 1 < RESERVE) {
    throw new Error(`holdout-run refuses: running would leave fewer than ${RESERVE} untouched apps`);
  }
  return apps.slice(0, apps.length - RESERVE);
}

export function runHoldout(input) {
  const chosen = holdoutPlan(input);
  mkdirSync(input.resultsDir, { recursive: true });
  const ran = [];
  for (const app of chosen) {
    const findings = input.scan(app);
    const file = join(input.resultsDir, `${app.name}-${input.release}.json`);
    writeFileSync(
      file,
      `${JSON.stringify({ app: app.name, release: input.release, findings, recall: app.reviewed === true ? 'reviewed' : 'unreviewed' }, null, 2)}\n`,
    );
    app.status = 'seen';
    app.firstRunDate = input.today;
    ran.push(app.name);
  }
  writeFileSync(input.holdoutsPath, `${JSON.stringify({ apps: input.apps }, null, 2)}\n`);
  return ran;
}

function git(args) {
  const result = spawnSync('git', args, { encoding: 'utf8' });
  if (result.status !== 0) return '';
  return result.stdout.trim();
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const release = arg('--release');
  if (!release) {
    console.error('holdout-run requires --release');
    process.exit(1);
  }
  const root = arg('--root') ?? process.cwd();
  const holdoutsPath = join(root, 'bench/holdouts.json');
  const doc = JSON.parse(readFileSync(holdoutsPath, 'utf8'));
  const head = git(['rev-parse', 'HEAD']);
  const tag = git(['describe', '--tags', '--exact-match', head]);
  const changed = git(['diff', '--name-only', `freeze-${release}`, 'HEAD']).split('\n').filter(Boolean);
  try {
    runHoldout({
      release,
      apps: doc.apps,
      holdoutsPath,
      resultsDir: join(root, 'bench/results'),
      headTag: tag,
      changedFiles: changed,
      today: new Date().toISOString().slice(0, 10),
      scan() {
        throw new Error('holdout-run scan is human-only');
      },
    });
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
