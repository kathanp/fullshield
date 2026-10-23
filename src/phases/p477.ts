import { Worker } from 'node:worker_threads';

import { lowerSource } from '../engine/ir.js';

export const SEEDS = [
  { family: 'binding', source: 'const value = 1;\n' },
  { family: 'call', source: 'function run() {\n  return 1;\n}\n' },
] as const;

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) {return undefined;}
  return argv[index + 1];
}

function isReject(err: unknown): boolean {
  if (!(err instanceof Error)) {return false;}
  return err.name === 'SyntaxError' || err.message.includes('Parsing error') || err.message.includes('rejected');
}

export function parseIr(source: string): 'ok' | 'reject' | 'crash' {
  try {
    lowerSource(source);
    return 'ok';
  } catch (err) {
    return isReject(err) ? 'reject' : 'crash';
  }
}

export function plantHang(fuelMs: number): Promise<void> {
  return new Promise((resolve) => {
    const worker = new Worker(new URL('../../scripts/phase477-hang.mjs', import.meta.url));
    const timer = setTimeout(() => {
      void worker.terminate().then(() => resolve());
    }, fuelMs);
    worker.once('error', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

export async function fuzz(options: { mutations: number; parser: string; fuelMs: number }): Promise<{ code: number; text: string }> {
  if (options.parser === 'hang') {
    await plantHang(options.fuelMs);
    return { code: 1, text: 'failed case: hang\n' };
  }
  for (const seed of SEEDS) {
    let ok = 0;
    const attempts: string[] = [seed.source];
    for (let i = 0; i < options.mutations; i += 1) {
      const at = i % Math.max(seed.source.length, 1);
      attempts.push(`${seed.source.slice(0, at)};${seed.source.slice(at)}`);
    }
    for (const source of attempts) {
      const status = options.parser === 'crash' ? 'crash' : options.parser === 'reject' ? 'reject' : parseIr(source);
      if (status === 'crash') {return { code: 1, text: 'failed case: crash\n' };}
      if (status === 'ok') {ok += 1;}
    }
    if (ok < 1) {return { code: 1, text: `zero successes ${seed.family}\n` };}
  }
  return { code: 0, text: 'fuzz parse passed\n' };
}

export async function main(argv: readonly string[]): Promise<number> {
  const mutations = Number(arg(argv, '--mutations') ?? '0');
  const parser = arg(argv, '--parser') ?? 'ir';
  const fuelMs = Number(arg(argv, '--fuel-ms') ?? '200');
  const result = await fuzz({ mutations, parser, fuelMs });
  if (result.code === 0) {process.stdout.write(result.text);}
  else {process.stderr.write(result.text);}
  return result.code;
}
