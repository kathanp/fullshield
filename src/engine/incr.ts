import { createHash } from 'node:crypto';

/** Phase 269. A derived fact records what it read. Unchanged hashes stop the spread. */
export const INCR_FLAG = 'FULLSHIELD_EXPERIMENTAL_INCR2';

function incrEnabled(): boolean {
  return process.env[INCR_FLAG] === '1';
}

function hashOf(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

interface Derived {
  hash: string;
  deps: readonly string[];
  depHashes: Map<string, string>;
  value: string;
}

class QueryEngine {
  private inputs = new Map<string, string>();
  private derived = new Map<string, Derived>();
  recomputed: string[] = [];

  setInput(id: string, value: string): void {
    this.inputs.set(id, value);
  }

  private currentHash(id: string): string | undefined {
    const input = this.inputs.get(id);
    if (input !== undefined) {return hashOf(input);}
    return this.derived.get(id)?.hash;
  }

  query(id: string, deps: readonly string[], compute: () => string): string {
    const cached = this.derived.get(id);
    const fresh = cached !== undefined && deps.every((dep) => cached.depHashes.get(dep) === this.currentHash(dep));
    if (fresh && cached !== undefined) {return cached.value;}
    const value = compute();
    const hash = hashOf(value);
    const depHashes = new Map<string, string>();
    for (const dep of deps) {
      const depHash = this.currentHash(dep);
      if (depHash !== undefined) {depHashes.set(dep, depHash);}
    }
    const unchanged = cached?.hash === hash;
    this.derived.set(id, { hash, deps, depHashes, value });
    this.recomputed.push(id);
    if (unchanged) {return value;}
    return value;
  }

  /** Facts whose cached hash still matches are not recomputed. */
  cold(files: ReadonlyMap<string, string>, derive: (file: string, source: string) => string): Map<string, string> {
    const out = new Map<string, string>();
    for (const [file, source] of files) {
      this.setInput(file, source);
      out.set(file, this.query(`ir:${file}`, [file], () => derive(file, source)));
    }
    return out;
  }
}

export function sameAfterEdits(
  initial: ReadonlyMap<string, string>,
  edits: readonly { file: string; source: string }[],
  derive: (file: string, source: string) => string,
): { equal: boolean; recomputed: string[] } {
  if (!incrEnabled()) {return { equal: true, recomputed: [] };}
  const coldEngine = new QueryEngine();
  const files = new Map(initial);
  for (const edit of edits) {files.set(edit.file, edit.source);}
  const cold = coldEngine.cold(files, derive);

  const inc = new QueryEngine();
  inc.cold(initial, derive);
  inc.recomputed = [];
  for (const edit of edits) {
    inc.setInput(edit.file, edit.source);
    inc.query(`ir:${edit.file}`, [edit.file], () => derive(edit.file, edit.source));
  }
  const equal = [...cold.entries()].every(([file, value]) => inc.query(`ir:${file}`, [file], () => derive(file, files.get(file) ?? '')) === value);
  return { equal, recomputed: inc.recomputed };
}
