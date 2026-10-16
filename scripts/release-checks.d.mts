export function parseVersion(value: string): { major: number; minor: number; patch: number };
export function bumpKind(
  fromVersion: string,
  toVersion: string,
): 'major' | 'minor' | 'patch' | 'none' | 'decrease';
export function requiredBump(signals: {
  newRuleIds?: string[];
  newCommands?: string[];
  newFlags?: string[];
  newExports?: string[];
  stableChanged?: boolean;
}): 'minor' | 'patch';
export function bumpSatisfies(actual: string, required: string): boolean;
export function baselineTag(tags: string[], headSha: string, tagSha: (tag: string) => string): string;
export function parseLeadingJson(text: string): unknown;
export function packReportEntry(report: unknown): {
  unpackedSize?: number;
  files?: unknown[];
};
export function packBudgetErrors(pack: {
  unpackedBytes: number;
  fileCount: number;
  hardDeps: string[];
  previousHardDeps: string[];
}): string[];
export function attestationsPresent(packument: { dist?: { attestations?: object } } | null): boolean;
export function addedLines(before: string[], after: string[]): string[];
export function diffFindingKeys(
  baseKeys: string[],
  headKeys: string[],
): { added: string[]; removed: string[]; changed: Array<{ from: string; to: string }> };
export function approvedDiffMatches(actual: string, approved: string): boolean;
export function formatSnapshotDiff(
  apps: Array<{
    app: string;
    added: string[];
    removed: string[];
    changed: Array<{ from: string; to: string }>;
  }>,
): string;
