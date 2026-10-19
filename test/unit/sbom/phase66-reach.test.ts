import { describe, expect, it } from 'vitest';

import type { Finding } from '../../../src/core/finding.js';
import { renderCycloneDx, validateCycloneDx15 } from '../../../src/sbom/cyclonedx.js';
import { buildOpenVex } from '../../../src/vex/index.js';

function vuln(extra: Partial<Finding> = {}): Finding {
  return {
    id: 'deadbeef',
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: 'Vulnerable dependency lodash@4.17.11',
    severity: 'high',
    confidence: 'high',
    snippet: 'lodash@4.17.11',
    message: 'lodash@4.17.11 is affected',
    remediation: 'upgrade',
    references: ['GHSA-test'],
    reachability: 'reachable',
    dependencyPath: ['lodash'],
    ...extra,
  };
}

describe('phase 66 SBOM reachability', () => {
  const components = [{ name: 'lodash', version: '4.17.11' }];

  it('omits properties when the flag is off and keeps CycloneDX 1.5 valid', () => {
    const doc = renderCycloneDx({ name: 'app', version: '1.0.0', components, findings: [vuln()] });
    expect(validateCycloneDx15(doc)).toEqual([]);
    const component = (doc.components as Array<Record<string, unknown>>)[0];
    expect(component?.properties).toBeUndefined();
  });

  it('adds reachability properties when asked and does not downgrade a malicious package', () => {
    const malicious: Finding = {
      ...vuln(),
      ruleId: 'DEPS-MALICIOUS-001',
      severity: 'critical',
      snippet: 'evil@1.0.0',
      reachability: 'not-imported',
    };
    const doc = renderCycloneDx({
      name: 'app',
      version: '1.0.0',
      components: [...components, { name: 'evil', version: '1.0.0' }],
      findings: [vuln(), malicious],
      includeReach: true,
    });
    expect(validateCycloneDx15(doc)).toEqual([]);
    const rows = doc.components as Array<{ name: string; properties?: Array<{ name: string; value: string }> }>;
    const lodash = rows.find((row) => row.name === 'lodash');
    expect(lodash?.properties?.find((prop) => prop.name === 'fullshield:reachability')?.value).toBe('reachable');
    expect(lodash?.properties?.find((prop) => prop.name === 'fullshield:dependencyPath')?.value).toBe('lodash');
    const vex = buildOpenVex([malicious]);
    const statements = vex.statements as Array<{ status?: string }>;
    expect(statements.every((statement) => statement.status !== 'not_affected')).toBe(true);
  });
});
