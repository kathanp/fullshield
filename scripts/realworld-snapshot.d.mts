import type { RealworldFinding, RealworldSpawn } from './realworld-lib.mjs';

export function runSnapshot(
  argv: readonly string[],
  deps?: {
    spawn?: RealworldSpawn;
    scanFindings?: (dir: string) => Promise<readonly RealworldFinding[]>;
  },
): Promise<number>;
