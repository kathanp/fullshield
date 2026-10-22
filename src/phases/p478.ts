import { parseLockfile } from '../modules/deps/lockfile.js';

export const LOCK_SEED = `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/alpha": { "version": "1.2.3" }
  }
}
`;

export const PACKUMENT_SEED = '{"name":"alpha","versions":{"1.2.3":{"version":"1.2.3"}}}\n';

export const HEADER_SEED = 'path: package/lib/index.js\n';

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function isReject(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.name === 'SyntaxError' || err.message.includes('rejected');
}

export function parseLock(text: string): 'ok' | 'reject' | 'crash' {
  try {
    const packages = parseLockfile('package-lock.json', text);
    return packages.length > 0 ? 'ok' : 'reject';
  } catch (err) {
    return isReject(err) ? 'reject' : 'crash';
  }
}

export function parsePackument(text: string): 'ok' | 'reject' | 'crash' {
  try {
    const doc: unknown = JSON.parse(text);
    if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return 'reject';
    const name = (doc as { name?: unknown }).name;
    return typeof name === 'string' && name.length > 0 ? 'ok' : 'reject';
  } catch (err) {
    return isReject(err) ? 'reject' : 'crash';
  }
}

/** Header path check from phase 179. A hostile path is rejected and not extracted. */
export function parseHeader(text: string): 'ok' | 'reject' | 'crash' {
  try {
    const line = text.split(/\r?\n/).find((row) => row.startsWith('path:'));
    if (line === undefined) return 'reject';
    const name = line.slice('path:'.length).trim();
    if (name.length === 0 || name.startsWith('/') || name.includes('..')) return 'reject';
    return 'ok';
  } catch (err) {
    return isReject(err) ? 'reject' : 'crash';
  }
}

const FAMILIES: Record<string, { seed: string; parse: (text: string) => 'ok' | 'reject' | 'crash' }> = {
  lockfile: { seed: LOCK_SEED, parse: parseLock },
  packument: { seed: PACKUMENT_SEED, parse: parsePackument },
  header: { seed: HEADER_SEED, parse: parseHeader },
};

export function fuzzLock(parser: string): { code: number; text: string } {
  for (const [family, spec] of Object.entries(FAMILIES)) {
    const status = parser === 'crash' ? 'crash' : parser === 'reject' ? 'reject' : spec.parse(spec.seed);
    if (status === 'crash') return { code: 1, text: 'failed case: crash\n' };
    if (status !== 'ok') return { code: 1, text: `zero successes ${family}\n` };
    if (parser === 'ir' && family === 'header' && spec.parse('path: ../etc/passwd\n') !== 'reject') {
      return { code: 1, text: 'hostile path was not rejected\n' };
    }
  }
  return { code: 0, text: 'fuzz lock passed\n' };
}

export function main(argv: readonly string[]): number {
  const parser = arg(argv, '--parser') ?? 'ir';
  const result = fuzzLock(parser);
  if (result.code === 0) process.stdout.write(result.text);
  else process.stderr.write(result.text);
  return result.code;
}
