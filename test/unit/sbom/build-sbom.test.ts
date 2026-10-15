import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { buildSbom } from '../../../src/sbom/index.js';
import { renderCycloneDx, validateCycloneDx15 } from '../../../src/sbom/cyclonedx.js';

describe('buildSbom fallbacks', () => {
  it('uses exact package.json pins when no lockfile exists', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-sbom-pins-'));
    try {
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({
          name: 'pin-app',
          version: '2.0.0',
          dependencies: { leftpad: '1.2.3' },
          devDependencies: { vitest: '^2.0.0' },
        }),
      );
      const doc = await buildSbom(dir);
      expect(validateCycloneDx15(doc)).toEqual([]);
      const bom = doc as { metadata: { component: { name: string; version: string } }; components: Array<{ name: string }> };
      expect(bom.metadata.component.name).toBe('pin-app');
      expect(bom.metadata.component.version).toBe('2.0.0');
      expect(bom.components.some((c) => c.name === 'leftpad')).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('tolerates a missing package.json', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-sbom-empty-'));
    try {
      const doc = await buildSbom(dir);
      expect(validateCycloneDx15(doc)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('validateCycloneDx15 rejects arrays; render includes license and non-GHSA vulns', () => {
    expect(validateCycloneDx15([])).toContain('CycloneDX document must be an object');
    const doc = renderCycloneDx({
      name: 'app',
      version: '1.0.0',
      components: [{ name: 'x', version: '1.0.0', license: 'MIT', purl: 'pkg:npm/x@1.0.0' }],
      findings: [
        {
          id: 'f1',
          ruleId: 'DEPS-VULN-001',
          module: 'deps',
          title: 'vuln',
          severity: 'high',
          confidence: 'high',
          message: 'bad',
          remediation: 'bump',
          references: ['https://example.com/advisory'],
        },
      ],
    });
    expect(validateCycloneDx15(doc)).toEqual([]);
    const bom = doc as { components: Array<{ licenses?: unknown }>; vulnerabilities: Array<{ id: string }> };
    expect(bom.components[0]?.licenses).toBeDefined();
    expect(bom.vulnerabilities[0]?.id).toBe('f1');
  });
});
