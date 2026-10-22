/**
 * Phase 356. Install-script network destinations.
 * Off unless FULLSHIELD_EXPERIMENTAL_NETDEST=1.
 * Hosts come from strings that reach a network or shell API. DNS is not resolved.
 */

import { interpretScript } from './p353.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NETDEST';
export const RULE = 'DEPS-SCRIPT-HOST-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface HostFinding {
  ruleId: typeof RULE;
  severity: 'medium';
  host: string;
  scriptKey: string;
  message: string;
}

export function scriptHosts(
  source: string,
  scriptKey: string,
  allow: readonly string[] = [],
  testFixture = false,
): HostFinding[] {
  if (!enabled()) {
    return [];
  }
  const abstract = interpretScript(source, scriptKey);
  const permitted = new Set<string>(['registry.npmjs.org', ...allow]);
  if (testFixture) {
    permitted.add('example.invalid');
  }
  const findings: HostFinding[] = [];
  for (const host of abstract.hosts) {
    if (permitted.has(host)) {
      continue;
    }
    findings.push({
      ruleId: RULE,
      severity: 'medium',
      host,
      scriptKey,
      message: `Install script ${scriptKey} reaches host ${host}.`,
    });
  }
  return findings;
}
