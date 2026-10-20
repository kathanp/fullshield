import type { CapabilityName } from './names.js';

export interface CapabilityPolicy {
  deny: Partial<Record<CapabilityName, readonly string[]>>;
  warn: Partial<Record<CapabilityName, readonly string[]>>;
}

function packageGlobMatches(pattern: string, name: string): boolean {
  let body = '^';
  for (const ch of pattern) {
    if (ch === '*') {body += '.*';}
    else if (/[\\^$+?.()|[\]{}]/.test(ch)) {body += `\\${ch}`;}
    else {body += ch;}
  }
  return new RegExp(`${body}$`).test(name);
}

export function policyAction(
  policy: CapabilityPolicy | undefined,
  capability: CapabilityName,
  names: readonly string[],
): 'deny' | 'warn' | undefined {
  if (policy === undefined) {return undefined;}
  const denied = policy.deny[capability] ?? [];
  if (names.some((name) => denied.some((pattern) => packageGlobMatches(pattern, name)))) {return 'deny';}
  const warned = policy.warn[capability] ?? [];
  if (names.some((name) => warned.some((pattern) => packageGlobMatches(pattern, name)))) {return 'warn';}
  return undefined;
}
