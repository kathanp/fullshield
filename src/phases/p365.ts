/**
 * Phase 365. Git dependency commit pin.
 * Off unless FULLSHIELD_EXPERIMENTAL_GITPIN=1.
 * Does not resolve a branch to a commit.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GITPIN';
export const PHASE_120_FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_GITDEP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

function phase120Enabled(): boolean {
  return process.env[PHASE_120_FLAG] === '1';
}

export interface GitPinFinding {
  ruleId: 'DEPS-GITPIN-001' | 'DEPS-GITDEP-001';
  severity: 'medium';
  specifier: string;
  message: string;
}

function isGitSpecifier(specifier: string): boolean {
  return /^(git\+|git:|github:|gitlab:|bitbucket:)/.test(specifier) || /^[^:\s]+\/[^:\s]+#.+/.test(specifier);
}

function gitRef(specifier: string): string | null {
  const hash = specifier.lastIndexOf('#');
  if (hash === -1) {
    return null;
  }
  return specifier.slice(hash + 1);
}

function isFullCommit(ref: string): boolean {
  return /^[0-9a-f]{40}$/i.test(ref);
}

export function gitPinFindings(specifier: string): GitPinFinding[] {
  if (!isGitSpecifier(specifier)) {
    return [];
  }
  const findings: GitPinFinding[] = [];
  if (phase120Enabled()) {
    findings.push({
      ruleId: 'DEPS-GITDEP-001',
      severity: 'medium',
      specifier,
      message: `${specifier} is a git dependency`,
    });
  }
  if (!enabled()) {
    return findings;
  }
  const ref = gitRef(specifier);
  if (ref !== null && isFullCommit(ref)) {
    return findings;
  }
  const short = ref !== null && /^[0-9a-f]{7,39}$/i.test(ref);
  findings.push({
    ruleId: 'DEPS-GITPIN-001',
    severity: 'medium',
    specifier,
    message: short
      ? `${specifier} is not pinned: the id is not 40 hex characters`
      : `${specifier} is not pinned to a full commit id`,
  });
  return findings;
}
