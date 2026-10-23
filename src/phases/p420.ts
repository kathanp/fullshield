/**
 * Phase 420. Fix batches.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIXGROUP=1.
 * Groups edits by directory and rule. Does not push and does not call a forge.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXGROUP';
export const DEFAULT_LINE_CAP = 400;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface BatchEdit {
  dir: string;
  ruleId: string;
  lines: number;
  disposition: 'safe' | 'review';
  path: string;
}

export interface FixBatch {
  id: string;
  directory: string;
  ruleId: string;
  disposition: 'safe' | 'review';
  paths: string[];
  lineCount: number;
}

function escapes(filePath: string): boolean {
  const normalized = filePath.replaceAll('\\', '/');
  return normalized.startsWith('../') || normalized === '..' || normalized.includes('/../');
}

export function groupFixes(edits: readonly BatchEdit[], lineCap = DEFAULT_LINE_CAP): { batches: FixBatch[]; refused: boolean } {
  if (!enabled()) {
    return { batches: [], refused: false };
  }
  let refused = false;
  const bins = new Map<string, BatchEdit[]>();
  for (const edit of edits) {
    const filePath = edit.path ?? '';
    if (filePath === '' || escapes(filePath)) {
      refused = true;
      continue;
    }
    const key = `${edit.dir}\0${edit.ruleId}`;
    const list = bins.get(key) ?? [];
    list.push(edit);
    bins.set(key, list);
  }
  const batches: FixBatch[] = [];
  let serial = 0;
  for (const [key, group] of bins) {
    const directory = key.split('\0')[0] ?? '.';
    const ruleId = key.split('\0')[1] ?? '';
    let current: BatchEdit[] = [];
    let lines = 0;
    const flush = (): void => {
      if (current.length === 0) {
        return;
      }
      batches.push({
        id: `batch-${serial}`,
        directory,
        ruleId,
        disposition: current.some((edit) => edit.disposition === 'review') ? 'review' : 'safe',
        paths: current.map((edit) => edit.path),
        lineCount: lines,
      });
      serial += 1;
      current = [];
      lines = 0;
    };
    for (const edit of group) {
      if (current.length > 0 && lines + edit.lines > lineCap) {
        flush();
      }
      current.push(edit);
      lines += edit.lines;
    }
    flush();
  }
  return { batches, refused };
}
