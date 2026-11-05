import { makeFindingId, type Finding } from '../core/finding.js';
import { findTyposquats } from '../modules/deps/typosquat.js';

const SCRIPT_KEYS = ['preinstall', 'install', 'postinstall'] as const;

export interface InstallFacts {
  name: string;
  version?: string;
  advisories?: string[];
  scripts?: Record<string, string>;
  previousScripts?: Record<string, string>;
  provenance?: boolean;
  publisher?: string;
  previousPublisher?: string;
  publishedAt?: string;
  now?: string;
  minAgeDays?: number;
}

function row(ruleId: string, title: string, message: string, severity: Finding['severity']): Finding {
  return {
    id: makeFindingId(ruleId, 'package.json', message),
    ruleId,
    module: 'deps',
    title,
    severity,
    confidence: 'high',
    file: 'package.json',
    message,
    remediation: 'Do not install this package. The package was not executed.',
  };
}

function scriptChanged(current: Record<string, string> | undefined, previous: Record<string, string> | undefined): string | undefined {
  if (current === undefined || previous === undefined) {return undefined;}
  for (const key of SCRIPT_KEYS) {
    const next = current[key];
    const prev = previous[key];
    if (next === prev) {continue;}
    if (next !== undefined && next !== prev) {return key;}
  }
  return undefined;
}

/** Static checks only. Unknown fields are not treated as failures. */
export function installFirewallFindings(facts: InstallFacts): Finding[] {
  const findings: Finding[] = [];
  for (const advisory of facts.advisories ?? []) {
    if (advisory.startsWith('MAL-')) {
      findings.push(row('SUPPLY-MAL-001', 'OSV malicious-package advisory', `${facts.name} is named by ${advisory}.`, 'critical'));
    }
  }
  const typos = findTyposquats(
    [{ name: facts.name, version: facts.version ?? '0.0.0', path: facts.name }],
    { directNames: new Set([facts.name]) },
  );
  for (const hit of typos) {
    findings.push(row('DEPS-TYPOSQUAT-001', 'Possible typosquat', `${hit.name} is 1 character from ${hit.lookalike}.`, 'high'));
  }
  const changed = scriptChanged(facts.scripts, facts.previousScripts);
  if (changed !== undefined) {
    findings.push(row('SUPPLY-SCRIPT-001', 'Install script changed', `${facts.name} ${changed} script changed from the previous version.`, 'high'));
  }
  if (facts.provenance === false) {
    findings.push(row('SUPPLY-PROVENANCE-001', 'Package has no npm provenance', `${facts.name} published without provenance.`, 'medium'));
  }
  if (
    facts.publisher !== undefined &&
    facts.previousPublisher !== undefined &&
    facts.publisher !== facts.previousPublisher
  ) {
    findings.push(row('SUPPLY-PUBLISHER-001', 'Package publisher changed', `${facts.name} publisher changed from ${facts.previousPublisher} to ${facts.publisher}.`, 'high'));
  }
  if (facts.publishedAt !== undefined && facts.minAgeDays !== undefined) {
    const published = Date.parse(facts.publishedAt);
    const now = Date.parse(facts.now ?? new Date(0).toISOString());
    if (Number.isFinite(published) && Number.isFinite(now)) {
      const ageDays = (now - published) / 86_400_000;
      if (ageDays < facts.minAgeDays) {
        findings.push(row('SUPPLY-AGE-001', 'Release is younger than policy', `${facts.name} is ${ageDays.toFixed(1)} days old. Policy is ${facts.minAgeDays} days.`, 'medium'));
      }
    }
  }
  return findings;
}
