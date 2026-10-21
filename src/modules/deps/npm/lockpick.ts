/** Phase 108. Off, shrinkwrap is not a lockfile. On, it is the lockfile only when `package-lock.json` is absent. */
export function pickNpmLock(files: readonly string[]): string | undefined {
  if (process.env.FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP !== '1') {return undefined;}
  if (!files.includes('npm-shrinkwrap.json')) {return undefined;}
  if (files.includes('package-lock.json')) {return undefined;}
  return 'npm-shrinkwrap.json';
}

export const NPM_LOCK_NAMES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
] as const;
