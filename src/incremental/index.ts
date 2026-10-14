import { spawnSync } from 'node:child_process';

export interface ChangedOptions {
  changed?: boolean;
  since?: string;
  experimental?: boolean;
  git?: (args: string[]) => string;
}

export function resolveChangedFiles(cwd: string, opts: ChangedOptions = {}): string[] {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') return [];
  if (!opts.changed && !opts.since) return [];
  const run =
    opts.git ??
    ((args: string[]) =>
      spawnSync('git', args, { cwd, encoding: 'utf8' }).stdout ?? '');
  const range = opts.since ?? 'HEAD';
  const out = opts.changed ? run(['diff', '--name-only', '--cached']) : run(['diff', '--name-only', range]);
  return out
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}
