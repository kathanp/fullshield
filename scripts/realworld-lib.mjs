/**
 * Shared helpers for the Phase 77 real-world precision gate.
 * Repos are materialized with git and scanned by FullShield. They are never
 * installed and never executed.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export function findingKey(finding) {
  const file = String(finding.file ?? '').replaceAll('\\', '/');
  const line = finding.line === undefined || finding.line === null ? '' : String(finding.line);
  return `${finding.ruleId}\t${file}\t${line}\t${finding.severity}`;
}

/** @param {string[]} baseKeys @param {string[]} headKeys */
export function diffKeys(baseKeys, headKeys) {
  const base = new Set(baseKeys);
  const head = new Set(headKeys);
  return {
    added: [...head].filter((key) => !base.has(key)).sort(),
    removed: [...base].filter((key) => !head.has(key)).sort(),
  };
}

/** Exit 1 when any added key is absent from the approved set. Removals do not fail. */
export function gateExitCode(addedKeys, approved) {
  return addedKeys.every((key) => approved.has(key)) ? 0 : 1;
}

/**
 * Read the human approval list. A missing file approves nothing.
 * This function only reads. It does not create or modify the file.
 * @param {string} file
 * @returns {Set<string>}
 */
export function readApprovedKeys(file) {
  if (!existsSync(file)) return new Set();
  const text = readFileSync(file, 'utf8');
  const keys = new Set();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    keys.add(trimmed);
  }
  return keys;
}

/** @param {Record<string, { sha: string | null, keys: string[] }>} repos */
export function buildSnapshot(repos) {
  return {
    generatedBy: 'scripts/realworld-snapshot.mjs',
    repos,
  };
}

/** @param {string} name @param {{ added: string[], removed: string[] }} diff */
export function formatRepoDiff(name, diff) {
  const lines = [name];
  for (const key of diff.removed) lines.push(`- ${key}`);
  for (const key of diff.added) lines.push(`+ ${key}`);
  return lines.join('\n');
}

export function loadRegistry(file) {
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  if (!Array.isArray(doc.repos)) throw new Error(`registry ${file} has no repos array`);
  return doc.repos;
}

export function argValue(argv, name, fallback) {
  const index = argv.indexOf(name);
  if (index === -1) return fallback;
  return argv[index + 1] ?? fallback;
}

export function stripExperimental(env) {
  const next = { ...env };
  for (const key of Object.keys(next)) {
    if (key.startsWith('FULLSHIELD_')) delete next[key];
  }
  return next;
}

export function parseScanJson(stdout) {
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start === -1 || end < start) throw new Error('scan json missing from output');
  return JSON.parse(stdout.slice(start, end + 1));
}

/**
 * Default-scan one checkout with the built CLI. cwd is the FullShield repo,
 * not the checkout, so the checkout's scripts are not started.
 */
export function scanWithCli(dir, cli, spawn, projectRoot) {
  if (!existsSync(cli)) throw new Error(`built CLI missing: ${cli}`);
  const result = spawn(process.execPath, [cli, 'scan', dir, '--json', '--offline'], {
    cwd: projectRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: stripExperimental(process.env),
  });
  if (result.status !== 0 && result.status !== 1) {
    const detail = result.stderr || result.stdout || result.error || '';
    throw new Error(`scan ${dir} exited ${result.status}: ${detail}`);
  }
  const report = parseScanJson(String(result.stdout ?? ''));
  return report.findings ?? [];
}

function gitSafety(hooksDir, attributesFile) {
  return [
    '-c',
    `core.hooksPath=${hooksDir}`,
    '-c',
    `core.attributesFile=${attributesFile}`,
    '-c',
    'submodule.recurse=false',
    '-c',
    'advice.detachedHead=false',
  ];
}

/**
 * Local `path` entries are used as-is (fixture repos). Remote entries are
 * fetched at their pin into the cache. Git hooks and attribute filters are
 * pointed at empty files so the checkout does not run repo code.
 * @param {{ name: string, path?: string, repo?: string, sha?: string }} entry
 * @param {string} cacheDir
 * @param {{ spawn?: typeof spawnSync }} [deps]
 */
export async function materializeRepo(entry, cacheDir, deps = {}) {
  if (entry.path) {
    const dir = resolve(entry.path);
    if (!existsSync(dir)) throw new Error(`fixture path missing: ${dir}`);
    return dir;
  }
  if (!entry.repo || !entry.sha) throw new Error(`repo ${entry.name ?? ''} needs repo and sha or path`);
  const spawn = deps.spawn ?? spawnSync;
  const dest = join(cacheDir, entry.name, entry.sha);
  const checkout = join(dest, 'repo');
  const ready = join(dest, 'ready');
  if (
    existsSync(ready) &&
    readFileSync(ready, 'utf8').trim() === entry.sha &&
    existsSync(join(checkout, '.git'))
  ) {
    return checkout;
  }
  mkdirSync(checkout, { recursive: true });
  const hooksDir = mkdtempSync(join(tmpdir(), 'fullshield-hooks-'));
  const attributesFile = join(hooksDir, 'attributes');
  writeFileSync(attributesFile, '');
  const git = (args) => {
    const result = spawn('git', [...gitSafety(hooksDir, attributesFile), ...args], {
      cwd: checkout,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_LFS_SKIP_SMUDGE: '1',
      },
    });
    if (result.status !== 0) {
      const detail = result.stderr || result.stdout || '';
      throw new Error(`git ${args.join(' ')} failed: ${detail}`);
    }
  };
  if (!existsSync(join(checkout, '.git'))) {
    git(['init']);
    git(['remote', 'add', 'origin', entry.repo]);
  }
  git(['fetch', '--depth', '1', 'origin', entry.sha]);
  git(['checkout', '--detach', 'FETCH_HEAD']);
  mkdirSync(dest, { recursive: true });
  writeFileSync(ready, `${entry.sha}\n`);
  return checkout;
}
