/**
 * Phase 371. Pinning policy audit.
 * Off unless FULLSHIELD_EXPERIMENTAL_PINPOLICY=1.
 * Distinct from phase 128. Emits nothing when the policy file is absent.
 */
import type { SupplyChainPolicy } from './p378.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PINPOLICY';
export const FLOAT_FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_FLOAT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ProdDep {
  name: string;
  spec: string;
}

export interface PinFinding {
  ruleId: 'DEPS-PIN-POLICY-001' | 'DEPS-FLOAT-001' | 'DEPS-FLOAT-002';
  severity: 'info' | 'low' | 'medium';
  name: string;
  message: string;
}

function isExact(spec: string): boolean {
  return spec === 'workspace:*' || /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(spec);
}

function floatId(spec: string): 'DEPS-FLOAT-001' | 'DEPS-FLOAT-002' | null {
  if (spec === '*' || spec === 'x' || spec === 'X' || spec === 'latest' || spec === '') {
    return 'DEPS-FLOAT-001';
  }
  if ((spec.startsWith('>=') || spec.startsWith('>')) && !spec.includes('<') && !spec.includes(' ')) {
    return 'DEPS-FLOAT-002';
  }
  return null;
}

export function pinPolicyFindings(deps: readonly ProdDep[], policy: SupplyChainPolicy | null): PinFinding[] {
  if (!enabled() || policy === null || policy.pinMode !== 'exact') {
    return [];
  }
  const severity = policy.pinSeverity ?? 'info';
  const floatOn = process.env[FLOAT_FLAG] === '1';
  const findings: PinFinding[] = [];
  for (const dep of deps) {
    if (isExact(dep.spec)) {
      continue;
    }
    findings.push({
      ruleId: 'DEPS-PIN-POLICY-001',
      severity,
      name: dep.name,
      message: `${dep.name} is not an exact production pin required by policy`,
    });
    if (floatOn) {
      const id = floatId(dep.spec);
      if (id !== null) {
        findings.push({
          ruleId: id,
          severity: id === 'DEPS-FLOAT-001' ? 'medium' : 'low',
          name: dep.name,
          message: `${dep.name} uses a general floating range`,
        });
      }
    }
  }
  return findings;
}
