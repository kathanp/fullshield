import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

export type UpgradeProof = 'upgrade-safe' | 'upgrade-breaks-tests';

export interface UpgradeInput {
  spec: string;
  install?: (dir: string, spec: string) => Promise<boolean>;
  test?: (dir: string) => Promise<boolean>;
}

async function npm(dir: string, args: string[]): Promise<boolean> {
  return await new Promise((resolve) => {
    const child = spawn('npm', args, { cwd: dir, stdio: 'ignore' });
    const timer = setTimeout(() => {
      child.kill();
      resolve(false);
    }, 60_000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve(code === 0);
    });
    child.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

/** Installs and tests in a temp directory. The working tree is not a target. */
export async function proveUpgrade(input: UpgradeInput): Promise<UpgradeProof> {
  const dir = await mkdtemp(join(tmpdir(), 'fs-upgrade-'));
  try {
    const install = input.install ?? ((target, spec) => npm(target, ['install', spec, '--ignore-scripts', '--prefix', target]));
    const test = input.test ?? ((target) => npm(target, ['test', '--silent']));
    const installed = await install(dir, input.spec);
    if (!installed) {return 'upgrade-breaks-tests';}
    const ok = await test(dir);
    return ok ? 'upgrade-safe' : 'upgrade-breaks-tests';
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
