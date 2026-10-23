/** Phase 259. Upgrade reachability across a dependency boundary. Never downgrade. */
export const DEPGRAPH_FLAG = 'FULLSHIELD_EXPERIMENTAL_DEPGRAPH';

function depGraphEnabled(): boolean {
  return process.env[DEPGRAPH_FLAG] === '1';
}

export type ReachClass =
  | 'not-imported'
  | 'reachability-unknown'
  | 'imported-not-called'
  | 'reachable-via-dependency'
  | 'function-reachable-via-dependency'
  | 'reachable'
  | 'symbol-not-called';

const RANK: Record<ReachClass, number> = {
  'not-imported': 0,
  'reachability-unknown': 1,
  'imported-not-called': 2,
  'symbol-not-called': 3,
  'reachable-via-dependency': 4,
  'function-reachable-via-dependency': 5,
  reachable: 6,
};

export function upgradeReach(current: ReachClass, next: ReachClass): ReachClass {
  return RANK[next] >= RANK[current] ? next : current;
}

export interface DepGraphResult {
  reachability: ReachClass;
  path: string[];
  read: string[];
}

const DEPTH_CAP = 3;

/**
 * `edges` maps `pkg.export` to callees `otherPkg.fn`.
 * The reader is invoked only for non-malicious packages on the walked path.
 */
export function functionReachable(
  current: ReachClass,
  rootExport: string,
  vulnerable: string,
  edges: ReadonlyMap<string, readonly string[]>,
  malicious: ReadonlySet<string>,
  readPackage: (name: string) => void,
): DepGraphResult {
  if (!depGraphEnabled()) {
    return { reachability: current, path: [], read: [] };
  }
  const read: string[] = [];
  const queue: { node: string; path: string[]; depth: number }[] = [{ node: rootExport, path: [rootExport], depth: 0 }];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const item = queue.shift();
    if (item === undefined || seen.has(item.node)) {continue;}
    seen.add(item.node);
    const pkg = item.node.split('.')[0] ?? '';
    if (malicious.has(pkg)) {continue;}
    if (!read.includes(pkg)) {
      read.push(pkg);
      readPackage(pkg);
    }
    if (item.node === vulnerable) {
      return {
        reachability: upgradeReach(current, 'function-reachable-via-dependency'),
        path: item.path,
        read,
      };
    }
    if (item.depth >= DEPTH_CAP) {continue;}
    for (const next of edges.get(item.node) ?? []) {
      queue.push({ node: next, path: [...item.path, next], depth: item.depth + 1 });
    }
  }
  return {
    reachability: upgradeReach(current, 'reachable-via-dependency'),
    path: [],
    read,
  };
}
