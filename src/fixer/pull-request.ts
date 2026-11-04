import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { spawn } from 'node:child_process';

export interface PrRun {
  status: number;
  stdout: string;
}

export type PrRunner = (args: readonly string[]) => Promise<PrRun>;

function commandPath(name: string): string {
  const pathValue = process.env.Path ?? process.env.PATH ?? '';
  const exts = process.platform === 'win32'
    ? (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';')
    : [''];
  for (const dir of pathValue.split(delimiter)) {
    if (dir.length === 0) {continue;}
    for (const ext of exts) {
      const candidate = join(dir, `${name}${ext}`);
      if (existsSync(candidate)) {return candidate;}
    }
  }
  return name;
}

async function gh(args: readonly string[]): Promise<PrRun> {
  return await new Promise((resolve) => {
    const child = spawn(commandPath('gh'), [...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: process.platform === 'win32',
    });
    let stdout = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.once('exit', (code) => {
      resolve({ status: code ?? 1, stdout });
    });
    child.once('error', () => {
      resolve({ status: 127, stdout: '' });
    });
  });
}

/** Opens one pull request. Never merges and never comments. */
export async function openVerifiedFixPr(input: {
  title: string;
  body: string;
  run?: PrRunner;
}): Promise<PrRun> {
  const args = ['pr', 'create', '--title', input.title, '--body', input.body];
  if (args.includes('merge') || args.includes('comment')) {
    throw new Error('fix --pr does not merge or comment');
  }
  const run = input.run ?? gh;
  return await run(args);
}
