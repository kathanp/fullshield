import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

const GENERATED = new Set(['dist', 'build', '.next', 'coverage', 'out']);

export interface SkippedCounts {
  total: number;
  oversize: number;
  minified: number;
  declaration: number;
  sourceMap: number;
  generated: number;
}

export function perf2Enabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_PERF2 === '1';
}

function pathReason(rel: string): 'generated' | 'declaration' | 'sourceMap' | undefined {
  const norm = rel.split('\\').join('/');
  const parts = norm.split('/');
  if (parts.slice(0, -1).some((part) => GENERATED.has(part))) {return 'generated';}
  if (norm.endsWith('.d.ts')) {return 'declaration';}
  if (norm.endsWith('.map')) {return 'sourceMap';}
  return undefined;
}

function isMinified(text: string): boolean {
  const lines = text.split(/\r?\n/);
  if (lines.some((line) => line.length > 50_000)) {return true;}
  const nonEmpty = lines.filter((line) => line.length > 0);
  if (nonEmpty.length === 0) {return false;}
  const avg = nonEmpty.reduce((sum, line) => sum + line.length, 0) / nonEmpty.length;
  return avg > 500;
}

/** Drop files that cannot be source. Counts are an info note, not findings. */
export async function partitionPerf2(
  cwd: string,
  files: readonly string[],
  maxBytes: number,
): Promise<{ kept: string[]; skipped: SkippedCounts }> {
  const skipped: SkippedCounts = {
    total: 0,
    oversize: 0,
    minified: 0,
    declaration: 0,
    sourceMap: 0,
    generated: 0,
  };
  const kept: string[] = [];
  for (const rel of files) {
    const reason = pathReason(rel);
    if (reason !== undefined) {
      skipped[reason] += 1;
      skipped.total += 1;
      continue;
    }
    try {
      const info = await stat(join(cwd, rel));
      if (info.size > maxBytes) {
        skipped.oversize += 1;
        skipped.total += 1;
        continue;
      }
      const text = await readFile(join(cwd, rel), 'utf8');
      if (isMinified(text)) {
        skipped.minified += 1;
        skipped.total += 1;
        continue;
      }
    } catch {
      kept.push(rel);
      continue;
    }
    kept.push(rel);
  }
  return { kept, skipped };
}
