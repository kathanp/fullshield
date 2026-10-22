import { scan } from '../core/engine.js';
import type { Finding } from '../core/finding.js';

export const NOT_ATTRIBUTED = 'These keys are not attributed to the id.';

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function keyOf(finding: Finding): string {
  return JSON.stringify({
    ruleId: finding.ruleId,
    file: finding.file ?? '',
    line: finding.line ?? 0,
    severity: finding.severity,
  });
}

export async function replayDirs(beforeDir: string, afterDir: string, id: string): Promise<string> {
  const before = await scan({ cwd: beforeDir, modules: ['sast'], offline: true });
  const after = await scan({ cwd: afterDir, modules: ['sast'], offline: true });
  const afterKeys = new Set(after.findings.map(keyOf));
  const beforeKeys = new Set(before.findings.map(keyOf));
  const lines = [NOT_ATTRIBUTED, `id-label: ${id}`, 'unreviewed'];
  for (const finding of before.findings) {
    const key = keyOf(finding);
    lines.push(afterKeys.has(key) ? `not-distinguishing ${key}` : `present-before ${key}`);
  }
  for (const finding of after.findings) {
    const key = keyOf(finding);
    if (!beforeKeys.has(key)) lines.push(`regressed ${key}`);
  }
  return lines.join('\n');
}

export async function main(argv: readonly string[]): Promise<number> {
  const before = arg(argv, '--before');
  const after = arg(argv, '--after');
  const id = arg(argv, '--id');
  if (before === undefined || after === undefined || id === undefined) {
    process.stderr.write('usage: --before <dir> --after <dir> --id <label>\n');
    return 2;
  }
  process.stdout.write(`${await replayDirs(before, after, id)}\n`);
  return 0;
}
