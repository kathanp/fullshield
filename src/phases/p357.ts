/**
 * Phase 357. Capability policy.
 * Off unless FULLSHIELD_EXPERIMENTAL_CAPPOLICY2=1.
 * An absent policy emits nothing. A draft is not enforced.
 */

import { interpretScript, type ScriptResult } from './p353.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CAPPOLICY2';
export const RULE = 'DEPS-CAP-POLICY-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type Capability = 'net' | 'fs-write' | 'env' | 'shell';

export interface CapabilityPolicy {
  draft?: boolean;
  packages: Readonly<Record<string, readonly Capability[]>>;
}

export interface CapFinding {
  ruleId: typeof RULE;
  severity: 'high';
  packageName: string;
  effect: Capability;
  message: string;
}

export function policyInit(effects: readonly Capability[]): { draft: true; packages: { '*': Capability[] } } {
  return { draft: true, packages: { '*': [...effects] } };
}

export function capabilityFindings(packageName: string, source: string, policy: CapabilityPolicy | null): CapFinding[] {
  if (!enabled() || policy === null || policy.draft === true) {
    return [];
  }
  const abstract: ScriptResult = interpretScript(source);
  const allowed = new Set<Capability>([...(policy.packages[packageName] ?? []), ...(policy.packages['*'] ?? [])]);
  const findings: CapFinding[] = [];
  for (const effect of abstract.effects) {
    if (allowed.has(effect)) {
      continue;
    }
    findings.push({
      ruleId: RULE,
      severity: 'high',
      packageName,
      effect,
      message: `Package ${packageName} may use ${effect}, which the policy does not allow.`,
    });
  }
  return findings;
}
