import { readFileSync } from 'node:fs';

import { scan } from '../core/engine.js';

interface HoldoutFile {
  apps?: Array<{ name?: string }>;
}

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) {return undefined;}
  return argv[index + 1];
}

function flagsOf(argv: readonly string[]): string[] {
  const flags: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--flag') {
      const name = argv[i + 1];
      if (name !== undefined) {flags.push(name);}
    }
  }
  return flags;
}

export function pathHasHoldout(repo: string, names: readonly string[]): string | undefined {
  const parts = repo.split(/[\\/]/);
  return names.find((name) => parts.includes(name));
}

export async function ablate(repo: string, flags: readonly string[], names: readonly string[]): Promise<string> {
  const blocked = pathHasHoldout(repo, names);
  if (blocked !== undefined) {throw new TypeError(`holdout path refused: ${blocked}`);}
  const rows: Array<{ flag: string; count: number }> = [];
  for (const flag of flags) {
    const previous = process.env[flag];
    process.env[flag] = '0';
    try {
      const result = await scan({ cwd: repo, modules: ['sast'], offline: true });
      rows.push({ flag, count: result.findings.length });
    } finally {
      if (previous === undefined) {delete process.env[flag];}
      else {process.env[flag] = previous;}
    }
  }
  return JSON.stringify({ unreviewed: true, rows });
}

export async function main(argv: readonly string[]): Promise<number> {
  const repo = arg(argv, '--repo');
  const registryPath = arg(argv, '--registry');
  if (repo === undefined || registryPath === undefined) {
    process.stderr.write('usage: --repo <dir> --registry <file> --flag <name>\n');
    return 2;
  }
  const registry = JSON.parse(readFileSync(registryPath, 'utf8')) as HoldoutFile;
  const names = (registry.apps ?? []).map((app) => app.name).filter((name): name is string => typeof name === 'string');
  try {
    const text = await ablate(repo, flagsOf(argv), names);
    process.stdout.write(`${text}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : 'ablation failed'}\n`);
    return 1;
  }
}
