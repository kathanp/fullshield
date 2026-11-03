import { spawn } from 'node:child_process';

export interface PrRun {
  status: number;
  stdout: string;
}

export type PrRunner = (args: readonly string[]) => Promise<PrRun>;

async function gh(args: readonly string[]): Promise<PrRun> {
  return await new Promise((resolve) => {
    const child = spawn('gh', [...args], { stdio: ['ignore', 'pipe', 'pipe'] });
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
