import { scan } from '../core/engine.js';

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) {return undefined;}
  return argv[index + 1];
}

export function byteMatch(runs: readonly string[]): boolean {
  const first = runs[0];
  if (first === undefined) {return false;}
  return runs.every((run) => run === first);
}

export function unorderedMapDouble(): readonly [string, string] {
  const left = JSON.stringify({ ruleId: 'R', file: 'a.js', line: 1, severity: 'high' });
  const right = JSON.stringify({ file: 'a.js', severity: 'high', line: 1, ruleId: 'R' });
  return [left, right];
}

async function once(dir: string, pool: string): Promise<string> {
  process.env.UV_THREADPOOL_SIZE = pool;
  const result = await scan({ cwd: dir, modules: ['sast'], offline: true });
  const keys = result.findings.map((finding) =>
    JSON.stringify({
      ruleId: finding.ruleId,
      file: finding.file ?? '',
      line: finding.line ?? 0,
      severity: finding.severity,
    }),
  );
  keys.sort();
  return keys.join('\n');
}

export async function threeRuns(dir: string): Promise<readonly string[]> {
  const pools = ['1', '4', '8'];
  const runs: string[] = [];
  for (const pool of pools) {runs.push(await once(dir, pool));}
  return runs;
}

export async function main(argv: readonly string[]): Promise<number> {
  if (argv.includes('--double')) {
    const runs = unorderedMapDouble();
    if (!byteMatch(runs)) {
      process.stderr.write('finding bytes differ\n');
      return 1;
    }
    process.stdout.write('runs match\n');
    return 0;
  }
  const dir = arg(argv, '--dir');
  if (dir === undefined) {
    process.stderr.write('usage: --dir <fixture>\n');
    return 2;
  }
  const runs = await threeRuns(dir);
  if (!byteMatch(runs)) {
    process.stderr.write('finding bytes differ\n');
    return 1;
  }
  process.stdout.write('runs match\n');
  return 0;
}
