import type { RealworldFinding, RealworldSpawn } from './realworld-lib.mjs';

export function runDiff(
  argv: readonly string[],
  deps?: {
    stdout?: (text: string) => void;
    stderr?: (text: string) => void;
    spawn?: RealworldSpawn;
    scanFindings?: (dir: string) => Promise<readonly RealworldFinding[]>;
  },
): Promise<number>;
