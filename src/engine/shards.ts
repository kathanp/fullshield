/** Phase 270. Workspace shards. Cross-shard facts are exported summaries only. */
export const SHARDS_FLAG = 'FULLSHIELD_EXPERIMENTAL_SHARDS';

function shardsEnabled(): boolean {
  return process.env[SHARDS_FLAG] === '1';
}

export interface ShardFile {
  workspace: string;
  loc: number;
  exports: readonly string[];
}

export interface ShardPlan {
  workspaces: string[];
  evicted: string[];
  exports: string[];
}

const DEFAULT_LOC = 500_000;
const DEFAULT_MEMORY_MB = 1536;

export function planShards(files: readonly ShardFile[], maxMemoryMb = DEFAULT_MEMORY_MB, locThreshold = DEFAULT_LOC): ShardPlan {
  if (!shardsEnabled()) {
    return { workspaces: [], evicted: [], exports: [] };
  }
  const byWorkspace = new Map<string, { loc: number; exports: string[] }>();
  for (const file of files) {
    const row = byWorkspace.get(file.workspace) ?? { loc: 0, exports: [] };
    row.loc += file.loc;
    row.exports.push(...file.exports);
    byWorkspace.set(file.workspace, row);
  }
  const total = [...byWorkspace.values()].reduce((sum, row) => sum + row.loc, 0);
  const workspaces = [...byWorkspace.keys()].sort();
  const exports = workspaces.flatMap((name) => byWorkspace.get(name)?.exports ?? []).sort();
  if (total < locThreshold) {
    return { workspaces, evicted: [], exports };
  }
  const evicted: string[] = [];
  let usedMb = 0;
  const order = [...workspaces].reverse();
  for (const name of order) {
    const loc = byWorkspace.get(name)?.loc ?? 0;
    const cost = Math.max(1, Math.ceil(loc / 1000));
    if (usedMb + cost > maxMemoryMb) {evicted.push(name);}
    else {usedMb += cost;}
  }
  return { workspaces, evicted, exports };
}

/** Sharded and unsharded runs expose the same export summaries. */
export function summariesMatch(files: readonly ShardFile[]): boolean {
  const sharded = planShards(files);
  const plain = [...files.flatMap((file) => file.exports)].sort();
  return sharded.exports.join('\n') === plain.join('\n');
}
