export type RealworldFinding = {
  ruleId?: string;
  file?: string;
  line?: number | null;
  severity?: string;
};

export type RealworldSpawn = (
  cmd: string,
  args: string[],
  opts?: { cwd?: string; encoding?: 'utf8' },
) => { status: number | null; stdout?: string; stderr?: string };

export function findingKey(finding: RealworldFinding): string;

export function diffKeys(
  baseKeys: readonly string[],
  headKeys: readonly string[],
): { added: string[]; removed: string[] };

export function gateExitCode(addedKeys: readonly string[], approved: { has(key: string): boolean }): number;

export function readApprovedKeys(file: string): Set<string>;

export function buildSnapshot(repos: Record<string, { sha: string | null; keys: readonly string[] }>): {
  generatedBy: string;
  repos: Record<string, { sha: string | null; keys: readonly string[] }>;
};

export function formatRepoDiff(name: string, diff: { added: readonly string[]; removed: readonly string[] }): string;

export function loadRegistry(file: string): Array<{ name?: string; path?: string; repo?: string; sha?: string }>;

export function argValue(argv: readonly string[], name: string, fallback: string): string;

export function stripExperimental(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv;

export function parseScanJson(stdout: string): RealworldFinding[];

export function scanWithCli(
  dir: string,
  cli: string,
  spawn: RealworldSpawn,
  projectRoot: string,
): RealworldFinding[];

export function materializeRepo(
  entry: { name?: string; path?: string; repo?: string; sha?: string },
  cacheDir: string,
  deps?: { spawn?: RealworldSpawn },
): Promise<string>;
