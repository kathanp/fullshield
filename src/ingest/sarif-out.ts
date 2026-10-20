import type { Finding, Severity } from '../core/finding.js';
import { packageVersion } from '../core/version.js';
import { SCHEMA_URI } from '../reporters/sarif.js';
import type { IngestLoad } from './load.js';

export function renderIngestSarif(loaded: IngestLoad): string {
  const runs = loaded.groups.map((group) => runOf(group.source, group.findings));
  runs.push(runOf('FullShield', loaded.findings));
  return JSON.stringify({ $schema: SCHEMA_URI, version: '2.1.0', runs }, null, 2);
}

function runOf(name: string, findings: readonly Finding[]): Record<string, unknown> {
  const rules = new Map<string, { id: string; shortDescription: { text: string } }>();
  for (const finding of findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, { id: finding.ruleId, shortDescription: { text: finding.title } });
    }
  }
  return {
    tool: {
      driver: {
        name,
        ...(name === 'FullShield' ? { version: packageVersion() } : {}),
        rules: [...rules.values()],
      },
    },
    results: findings.map(resultOf),
  };
}

function resultOf(finding: Finding): Record<string, unknown> {
  const location = locationOf(finding);
  return {
    ruleId: finding.ruleId,
    level: levelOf(finding.severity),
    message: { text: finding.message },
    ...(location === undefined ? {} : { locations: [location] }),
    properties: propertiesOf(finding),
  };
}

function locationOf(finding: Finding): Record<string, unknown> | undefined {
  if (finding.file === undefined) {return undefined;}
  const region = finding.line === undefined ? undefined : { startLine: finding.line };
  return {
    physicalLocation: {
      artifactLocation: { uri: finding.file.replace(/\\/g, '/') },
      ...(region === undefined ? {} : { region }),
    },
  };
}

function propertiesOf(finding: Finding): Record<string, unknown> {
  return {
    source: finding.source,
    sources: finding.sources ?? [],
    externalRuleId: finding.externalRuleId,
    externalSeverity: finding.externalSeverity,
    ...(finding.reachability === undefined ? {} : { reachability: finding.reachability }),
    ...(finding.sinkClass === undefined ? {} : { sinkClass: finding.sinkClass }),
    ...(finding.routeExposure === undefined ? {} : { routeExposure: finding.routeExposure }),
  };
}

function levelOf(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') {return 'error';}
  if (severity === 'medium') {return 'warning';}
  return 'note';
}
