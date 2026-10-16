#!/usr/bin/env node
/**
 * Byte-identical default-scan check.
 *
 * Builds `scan --json --offline-safe` at --base and --head, then diffs
 * findings (ruleId, file, line, severity) on:
 *   - test/fixtures/vulnerable-app
 *   - test/fixtures/clean-app
 *   - every public bench app (nodegoat, juice-shop, dvna, goof, vulnerable-node)
 *
 * Default --base is the parent of the first `phase-29` commit on --head.
 * Exit 0 if findings match; 1 if they differ. Run before every remaining merge.
 *
 *   node scripts/default-scan-diff.mjs
 *   node scripts/default-scan-diff.mjs --base be68e49 --head HEAD
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';

const BENCH_APPS = [
  {
    id: 'nodegoat',
    repo: 'https://github.com/OWASP/NodeGoat.git',
    sha: 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8',
    dirs: ['NodeGoat', 'nodegoat'],
  },
  {
    id: 'juice-shop',
    repo: 'https://github.com/juice-shop/juice-shop.git',
    sha: 'e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4',
    dirs: ['juice-shop'],
  },
  {
    id: 'dvna',
    repo: 'https://github.com/appsecco/dvna.git',
    sha: '9ba473add536f66ac9007966acb2a775dd31277a',
    dirs: ['dvna'],
  },
  {
    id: 'goof',
    repo: 'https://github.com/snyk-labs/nodejs-goof.git',
    sha: 'add14ba59e98240d9e00a235dd7d42cd61ae9912',
    dirs: ['goof', 'nodejs-goof'],
  },
  {
    id: 'vulnerable-node',
    repo: 'https://github.com/cr0hn/vulnerable-node.git',
    sha: 'd68f2a3c9277ece2c2feb9976052033bdecd7fbe',
    dirs: ['vulnerable-node'],
  },
];

function argValue(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return fallback;
  return process.argv[idx + 1] ?? fallback;
}

function git(args, cwd = root) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
}

function resolveHead(raw) {
  return git(['rev-parse', raw]);
}

function firstPhase29Parent(headSha) {
  const log = git(['log', '--reverse', '--format=%H %s', `${headSha}`]);
  for (const line of log.split('\n')) {
    const space = line.indexOf(' ');
    const sha = line.slice(0, space);
    const subject = line.slice(space + 1);
    if (subject.startsWith('phase-29')) {
      return git(['rev-parse', `${sha}^`]);
    }
  }
  throw new Error('could not find a phase-29 commit on --head to derive --base');
}

function npmRun(script, cwd) {
  const result = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['run', script], {
    cwd,
    encoding: 'utf8',
    shell: isWindows,
    env: { ...process.env, CI: '1' },
  });
  if (result.status !== 0) {
    throw new Error(`npm run ${script} in ${cwd} failed:\n${result.stderr}\n${result.stdout}`);
  }
}

function buildScanner(sha) {
  const dest = mkdtempSync(join(tmpdir(), `fullshield-scan-${sha.slice(0, 8)}-`));
  git(['worktree', 'add', '--detach', dest, sha]);
  const modules = join(root, 'node_modules');
  if (existsSync(modules) && !existsSync(join(dest, 'node_modules'))) {
    spawnSync('ln', ['-s', modules, join(dest, 'node_modules')], { encoding: 'utf8' });
  } else if (!existsSync(join(dest, 'node_modules'))) {
    const ci = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['ci'], {
      cwd: dest,
      encoding: 'utf8',
      shell: isWindows,
    });
    if (ci.status !== 0) throw new Error(`npm ci failed in ${dest}: ${ci.stderr}`);
  }
  npmRun('build', dest);
  const cli = join(dest, 'dist', 'cli', 'index.js');
  if (!existsSync(cli)) throw new Error(`built CLI missing: ${cli}`);
  return { sha, dest, cli };
}

function cloneBench(app, benchHome) {
  for (const name of app.dirs) {
    const existing = join(benchHome, name);
    if (existsSync(join(existing, '.git')) || existsSync(join(existing, 'package.json'))) {
      return existing;
    }
  }
  mkdirSync(benchHome, { recursive: true });
  const dest = join(benchHome, app.dirs[0]);
  if (existsSync(dest)) return dest;
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
  const init = spawnSync('git', ['init', dest], { encoding: 'utf8', env });
  if (init.status !== 0) throw new Error(`git init ${dest}: ${init.stderr}`);
  spawnSync('git', ['-C', dest, 'remote', 'add', 'origin', app.repo], { encoding: 'utf8', env });
  const fetch = spawnSync('git', ['-C', dest, 'fetch', '--depth', '1', 'origin', app.sha], {
    encoding: 'utf8',
    env,
  });
  if (fetch.status !== 0) throw new Error(`git fetch ${app.repo} ${app.sha}: ${fetch.stderr}`);
  const co = spawnSync('git', ['-C', dest, 'checkout', '--detach', 'FETCH_HEAD'], {
    encoding: 'utf8',
    env,
  });
  if (co.status !== 0) throw new Error(`git checkout ${app.id}: ${co.stderr}`);
  return dest;
}

function findingKey(f) {
  const file = String(f.file ?? '').replaceAll('\\', '/');
  const line = f.line == null ? '' : String(f.line);
  return `${f.ruleId}\t${file}\t${line}\t${f.severity}`;
}

function parseScanJson(stdout) {
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) {
    throw new Error(`scan json missing from output:\n${stdout.slice(0, 500)}`);
  }
  return JSON.parse(stdout.slice(start, end + 1));
}

function scanApp(cli, appDir) {
  const result = spawnSync(process.execPath, [cli, 'scan', appDir, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      FULLSHIELD_EXPERIMENTAL_CLASSES: '',
      FULLSHIELD_EXPERIMENTAL_FRAMEWORKS: '',
      FULLSHIELD_EXPERIMENTAL_SAST_GAPS: '',
    },
  });
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(
      `scan ${appDir} with ${cli} exited ${result.status}:\n${result.stderr}\n${result.stdout.slice(0, 800)}`,
    );
  }
  const report = parseScanJson(result.stdout);
  const keys = (report.findings ?? []).map(findingKey).sort();
  return { keys, total: keys.length };
}

function diffKeys(baseKeys, headKeys) {
  const baseSet = new Set(baseKeys);
  const headSet = new Set(headKeys);
  const added = headKeys.filter((k) => !baseSet.has(k));
  const removed = baseKeys.filter((k) => !headSet.has(k));
  return { added, removed };
}

function main() {
  const headRaw = argValue('--head', 'HEAD');
  const head = resolveHead(headRaw);
  const baseRaw = argValue('--base', '');
  const base = resolveHead(baseRaw === '' ? firstPhase29Parent(head) : baseRaw);
  const benchHome = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');
  const cacheDir = join(tmpdir(), 'fullshield-default-scan-cache');
  mkdirSync(cacheDir, { recursive: true });

  console.log(`default-scan-diff base=${base.slice(0, 12)} head=${head.slice(0, 12)}`);

  const apps = [
    { id: 'vulnerable-app', dir: join(root, 'test', 'fixtures', 'vulnerable-app') },
    { id: 'clean-app', dir: join(root, 'test', 'fixtures', 'clean-app') },
    ...BENCH_APPS.map((app) => ({ id: app.id, dir: cloneBench(app, benchHome) })),
  ];

  const worktrees = [];
  let failed = 0;
  try {
    const scanners = {};
    for (const sha of [base, head]) {
      const cacheCli = join(cacheDir, `cli-${sha}`, 'dist', 'cli', 'index.js');
      if (existsSync(cacheCli)) {
        scanners[sha] = { sha, dest: join(cacheDir, `cli-${sha}`), cli: cacheCli };
        console.log(`  reuse built CLI ${sha.slice(0, 12)}`);
        continue;
      }
      const built = buildScanner(sha);
      worktrees.push(built.dest);
      scanners[sha] = built;
      console.log(`  built CLI ${sha.slice(0, 12)}`);
    }

    for (const app of apps) {
      const baseScan = scanApp(scanners[base].cli, app.dir);
      const headScan = scanApp(scanners[head].cli, app.dir);
      const { added, removed } = diffKeys(baseScan.keys, headScan.keys);
      const ok = added.length === 0 && removed.length === 0;
      const mark = ok ? 'IDENTICAL' : 'DRIFT';
      console.log(
        `  ${mark} ${app.id}: base=${baseScan.total} head=${headScan.total} added=${added.length} removed=${removed.length}`,
      );
      if (!ok) {
        failed += 1;
        for (const row of removed.slice(0, 40)) console.log(`    - ${row.replaceAll('\t', ' ')}`);
        for (const row of added.slice(0, 40)) console.log(`    + ${row.replaceAll('\t', ' ')}`);
        if (removed.length + added.length > 80) {
          console.log(`    … ${removed.length + added.length - 80} more`);
        }
      }
      writeFileSync(
        join(cacheDir, `${app.id}-${base.slice(0, 8)}-${head.slice(0, 8)}.json`),
        JSON.stringify({ app: app.id, base, head, added, removed, baseCount: baseScan.total, headCount: headScan.total }, null, 2),
      );
    }
  } finally {
    for (const dest of worktrees) {
      spawnSync('git', ['worktree', 'remove', '--force', dest], { cwd: root, encoding: 'utf8' });
      rmSync(dest, { recursive: true, force: true });
    }
  }

  if (failed > 0) {
    console.error(`\nDEFAULT SCAN DRIFT: ${failed} app(s) differ (ruleId, file, line, severity).`);
    process.exit(1);
  }
  console.log('\nDEFAULT SCAN IDENTICAL across vulnerable-app, clean-app, and every bench app.');
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
}
