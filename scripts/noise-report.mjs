#!/usr/bin/env node
/**
 * Default-scan noise table for the pinned tuning/seen bench apps.
 * Does not scan untouched holdouts (those stay unscanned until a release).
 *
 *   node scripts/noise-report.mjs
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const benchHome = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');

const APPS = [
  { id: 'nodegoat', dirs: ['NodeGoat', 'nodegoat'] },
  { id: 'juice-shop', dirs: ['juice-shop'] },
  { id: 'dvna', dirs: ['dvna'] },
  { id: 'goof', dirs: ['goof', 'nodejs-goof'] },
  { id: 'vulnerable-node', dirs: ['vulnerable-node'] },
];

const NOISE_PATH = /(?:^|\/)(node_modules|vendor|vendored|third_party|third-party|compiled|dist|build|\.next|coverage|test|tests|__tests__|fixtures?)(?:\/|$)/;
const MINIFIED = /\.min\.js$/;

function moduleOf(ruleId) {
  if (ruleId.startsWith('DEPS-')) return 'deps';
  if (ruleId.startsWith('SAST-')) return 'sast';
  if (ruleId.startsWith('SECRET-')) return 'secrets';
  if (ruleId.startsWith('CONFIG-')) return 'config';
  return 'other';
}

function resolveApp(dirs) {
  for (const name of dirs) {
    const dir = join(benchHome, name);
    if (existsSync(join(dir, 'package.json'))) return dir;
  }
  return undefined;
}

function parseScanJson(stdout) {
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('scan json missing');
  return JSON.parse(stdout.slice(start, end + 1));
}

function scan(dir) {
  const cli = join(root, 'dist', 'cli', 'index.js');
  if (!existsSync(cli)) throw new Error('dist/cli/index.js missing. Run npm run build first.');
  const result = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(`scan ${dir} exited ${result.status}\n${result.stderr}`);
  }
  return parseScanJson(result.stdout);
}

function main() {
  const rows = [];
  const flags = [];
  for (const app of APPS) {
    const dir = resolveApp(app.dirs);
    if (dir === undefined) {
      console.log(`# ${app.id}: checkout missing under ${benchHome}`);
      continue;
    }
    const report = scan(dir);
    const counts = new Map();
    const perFile = new Map();
    const perSink = new Map();
    for (const finding of report.findings ?? []) {
      const ruleId = String(finding.ruleId ?? '');
      const module = finding.module ?? moduleOf(ruleId);
      const severity = String(finding.severity ?? '');
      const key = `${app.id}\t${module}\t${ruleId}\t${severity}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
      const file = String(finding.file ?? '');
      const fileKey = `${ruleId}\0${file}`;
      perFile.set(fileKey, (perFile.get(fileKey) ?? 0) + 1);
      const sinkKey = `${ruleId}\0${file}\0${finding.line ?? ''}`;
      perSink.set(sinkKey, (perSink.get(sinkKey) ?? 0) + 1);
      if (NOISE_PATH.test(file) || MINIFIED.test(file)) {
        flags.push(`${app.id} path ${ruleId} ${file}:${finding.line ?? ''}`);
      }
    }
    for (const [key, count] of counts) {
      const [id, module, ruleId, severity] = key.split('\t');
      rows.push({ id, module, ruleId, severity, count });
    }
    for (const [key, count] of perFile) {
      if (count < 8) continue;
      const [ruleId, file] = key.split('\0');
      flags.push(`${app.id} file-hot ${count}x ${ruleId} ${file}`);
    }
    for (const [key, count] of perSink) {
      if (count < 2) continue;
      const [ruleId, file, line] = key.split('\0');
      flags.push(`${app.id} sink-hot ${count}x ${ruleId} ${file}:${line}`);
    }
    const depPaths = (report.findings ?? []).filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && Array.isArray(f.dependencyPaths) && f.dependencyPaths.length > 1,
    );
    if (depPaths.length > 0) {
      flags.push(`${app.id} deps grouped with multiple paths: ${depPaths.length}`);
    }
    console.log(`# ${app.id} total ${report.findings?.length ?? 0}`);
  }
  rows.sort((a, b) => b.count - a.count || a.id.localeCompare(b.id) || a.ruleId.localeCompare(b.ruleId));
  console.log('app\tmodule\truleId\tseverity\tcount');
  for (const row of rows) {
    console.log(`${row.id}\t${row.module}\t${row.ruleId}\t${row.severity}\t${row.count}`);
  }
  console.log('# flags');
  for (const flag of flags) console.log(flag);
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
