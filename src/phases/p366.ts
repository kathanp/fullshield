/**
 * Phase 366. Scoped names that resolve to the public registry.
 * Off unless FULLSHIELD_EXPERIMENTAL_INTERNALPUB=1.
 * Does not query npm. The resolved URL is already in the lock.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_INTERNALPUB';
export const POLICY_FLAG = 'FULLSHIELD_EXPERIMENTAL_SCPOLICY';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PublicScopeInput {
  rootPrivate: boolean;
  rootName: string;
  dependencyName: string;
  /** Lock resolved URL, or a link:/file: specifier. */
  resolved: string;
  /** Hosts from policy `privateRegistryHosts`. Null when policy is off or absent. */
  policyPrivateHosts: readonly string[] | null;
}

export interface PublicScopeFinding {
  ruleId: 'DEPS-PUBLIC-SCOPE-001';
  severity: 'medium';
  dependencyName: string;
  host: string;
  message: string;
}

function scopeOf(name: string): string | null {
  if (!name.startsWith('@')) {
    return null;
  }
  const slash = name.indexOf('/');
  if (slash === -1) {
    return null;
  }
  return name.slice(0, slash);
}

export function publicScopeFindings(input: PublicScopeInput): PublicScopeFinding[] {
  if (!enabled()) {
    return [];
  }
  if (input.resolved.startsWith('link:') || input.resolved.startsWith('file:')) {
    return [];
  }
  let host = '';
  try {
    host = new URL(input.resolved).host;
  } catch {
    return [];
  }
  if (host !== 'registry.npmjs.org') {
    return [];
  }
  const depScope = scopeOf(input.dependencyName);
  const rootScope = scopeOf(input.rootName);
  const scopeMatch = depScope !== null && depScope === rootScope;
  if (!input.rootPrivate && !scopeMatch) {
    return [];
  }
  const policyOn = process.env[POLICY_FLAG] === '1';
  if (policyOn && input.policyPrivateHosts !== null && input.policyPrivateHosts.includes(host)) {
    return [];
  }
  return [
    {
      ruleId: 'DEPS-PUBLIC-SCOPE-001',
      severity: 'medium',
      dependencyName: input.dependencyName,
      host,
      message: `Locked tarball host for ${input.dependencyName} is the public registry (${host}). Policy key privateRegistryHosts can allow the host. The package is not claimed to be absent.`,
    },
  ];
}
