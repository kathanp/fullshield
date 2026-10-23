/**
 * Phase 360. Repository URL mismatch.
 * Off unless FULLSHIELD_EXPERIMENTAL_REPOMISMATCH=1.
 * Normalizes git+https, a trailing .git, ssh versus https, and directory fragments.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REPOMISMATCH';
export const RULE = 'DEPS-REPO-MISMATCH-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface RepoInput {
  packageName: string;
  packument: string | null;
  tarball: string | null;
  git?: string | null;
}

export interface RepoFinding {
  ruleId: typeof RULE;
  severity: 'medium';
  packageName: string;
  urls: string[];
  message: string;
}

export interface RepoResult {
  findings: RepoFinding[];
  events: { code: 271; file: string; detail: string }[];
}

function normalizeRepoUrl(raw: string): string {
  let url = raw.trim().replace(/#.*$/, '').replace(/^git\+/, '');
  const scp = /^git@([^:]+):(.+)$/.exec(url);
  if (scp?.[1] !== undefined && scp[2] !== undefined) {
    url = `https://${scp[1]}/${scp[2]}`;
  }
  const ssh = /^ssh:\/\/(?:git@)?([^/]+)\/(.+)$/.exec(url);
  if (ssh?.[1] !== undefined && ssh[2] !== undefined) {
    url = `https://${ssh[1]}/${ssh[2]}`;
  }
  url = url.replace(/^https?:\/\//, '').replace(/\.git$/, '').replace(/\/$/, '');
  return url.toLowerCase();
}

export function repoMismatch(input: RepoInput): RepoResult {
  if (!enabled()) {
    return { findings: [], events: [] };
  }
  if (input.tarball === null || input.packument === null) {
    return { findings: [], events: [{ code: 271, file: input.packageName, detail: 'missing tarball cache' }] };
  }
  const pairs: [string, string][] = [[input.packument, input.tarball]];
  if (input.git !== undefined && input.git !== null) {
    pairs.push([input.packument, input.git]);
  }
  for (const [left, right] of pairs) {
    if (normalizeRepoUrl(left) === normalizeRepoUrl(right)) {
      continue;
    }
    return {
      findings: [
        {
          ruleId: RULE,
          severity: 'medium',
          packageName: input.packageName,
          urls: [left, right],
          message: `Repository URL mismatch for ${input.packageName} between ${left} and ${right}.`,
        },
      ],
      events: [],
    };
  }
  return { findings: [], events: [] };
}
