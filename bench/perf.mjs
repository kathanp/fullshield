#!/usr/bin/env node
/**
 * Performance harness. Records a number only after a real local run.
 *
 *   node bench/perf.mjs            # leave an existing measurement alone
 *   node bench/perf.mjs --measure  # time next, nest, and undici when checked out
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const baselinePath = join(root, 'bench', 'perf-baseline.json');
const home = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');
const wanted = ['next', 'nest', 'undici'];

export function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length === 0) return 0;
  if (sorted.length % 2 === 1) return sorted[mid] ?? 0;
  return ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
}

/** True when the new p50 is more than 15% slower. */
export function regressed(previous, next) {
  if (!(previous > 0) || !(next > 0)) return false;
  return next > previous * 1.15;
}

function readBaseline() {
  if (!existsSync(baselinePath)) return null;
  return JSON.parse(readFileSync(baselinePath, 'utf8'));
}

function timeScan(dir, args) {
  const cli = join(root, 'dist', 'cli', 'index.js');
  const started = process.hrtime.bigint();
  const result = spawnSync('/usr/bin/time', ['-l', process.execPath, cli, 'scan', dir, '--json', '--offline-safe', ...args], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const rss = Number((result.stderr.match(/(\d+)\s+maximum resident set size/) ?? [])[1] ?? 0);
  return { elapsedMs, rssBytes: rss, status: result.status, signal: result.signal };
}

function measure() {
  const present = wanted.filter((name) => existsSync(join(home, name, 'package.json')));
  if (present.length < wanted.length) {
    const previous = readBaseline();
    if (previous?.measured === true) {
      console.log('repos are not checked out; leaving the measured baseline in place');
      return;
    }
    const doc = {
      measured: false,
      reason: 'next, nest, and undici are not all checked out. No timing or memory number is recorded.',
      targets: { coldSeconds: 60, warmSeconds: 20, incrementalSeconds: 5, peakMemoryMb: 1536 },
    };
    writeFileSync(baselinePath, `${JSON.stringify(doc, null, 2)}\n`);
    console.log(doc.reason);
    return;
  }
  const cli = join(root, 'dist', 'cli', 'index.js');
  if (!existsSync(cli)) throw new Error('dist/cli/index.js missing. Run npm run build first.');
  const apps = {};
  for (const name of wanted) {
    const dir = join(home, name);
    const cold = [timeScan(dir, []), timeScan(dir, []), timeScan(dir, [])];
    const warm = timeScan(dir, []);
    const incremental = timeScan(dir, ['--changed']);
    const coldMs = cold.map((row) => row.elapsedMs);
    const peak = Math.max(...cold.map((row) => row.rssBytes), warm.rssBytes, incremental.rssBytes);
    const finished = (row) => row.status === 0 || row.status === 1;
    apps[name] = {
      coldMs,
      coldP50Ms: median(coldMs),
      warmMs: warm.elapsedMs,
      incrementalMs: incremental.elapsedMs,
      peakRssBytes: peak,
      statuses: [...cold, warm, incremental].map((row) => row.status),
      signals: [...cold, warm, incremental].map((row) => row.signal),
      finished: cold.every(finished) && finished(warm) && finished(incremental),
    };
    console.log(
      `${name} cold p50 ${(apps[name].coldP50Ms / 1000).toFixed(1)}s warm ${(warm.elapsedMs / 1000).toFixed(1)}s incremental ${(incremental.elapsedMs / 1000).toFixed(1)}s peak ${(peak / (1024 * 1024)).toFixed(0)}MB`,
    );
  }
  const previous = readBaseline();
  const doc = {
    measured: true,
    measuredAt: new Date().toISOString(),
    targets: { coldSeconds: 60, warmSeconds: 20, incrementalSeconds: 5, peakMemoryMb: 1536 },
    apps,
  };
  const failures = [];
  for (const [name, row] of Object.entries(apps)) {
    if (row.finished !== true) failures.push(`${name} scan did not finish`);
    if (row.coldP50Ms > 60_000) failures.push(`${name} cold p50 ${row.coldP50Ms}ms`);
    if (row.warmMs > 20_000) failures.push(`${name} warm ${row.warmMs}ms`);
    if (row.incrementalMs > 5_000) failures.push(`${name} incremental ${row.incrementalMs}ms`);
    if (row.peakRssBytes > 1536 * 1024 * 1024) failures.push(`${name} peak rss ${row.peakRssBytes}`);
    const before = previous?.apps?.[name]?.coldP50Ms;
    if (regressed(before, row.coldP50Ms)) failures.push(`${name} cold p50 regressed`);
  }
  doc.withinTargets = failures.length === 0;
  doc.misses = failures;
  writeFileSync(baselinePath, `${JSON.stringify(doc, null, 2)}\n`);
  if (failures.length > 0) {
    console.error(failures.join('\n'));
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  if (process.argv.includes('--measure')) measure();
  else {
    const previous = readBaseline();
    if (previous?.measured === true) console.log('measured baseline present; pass --measure to run again');
    else measure();
  }
}
