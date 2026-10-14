import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { renderCycloneDx, validateCycloneDx15 } from '../../../src/sbom/cyclonedx.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');

describe('CycloneDX 1.5 SBOM', () => {
  it('emits a document that validates and includes lockfile packages + vuln refs', async () => {
    const result = await scan({ cwd: vulnerableApp, modules: ['deps'] });
    const doc = renderCycloneDx({
      name: 'vulnerable-app',
      version: '1.0.0',
      components: [
        { name: 'lodash', version: '4.17.11', license: 'MIT' },
        { name: 'minimist', version: '1.2.0' },
      ],
      findings: result.findings.filter((f) => f.ruleId === 'DEPS-VULN-001'),
    });
    expect(validateCycloneDx15(doc)).toEqual([]);
    const bom = doc as {
      bomFormat: string;
      specVersion: string;
      components: Array<{ name: string }>;
      vulnerabilities: unknown[];
    };
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    expect(bom.components.some((c) => c.name === 'lodash')).toBe(true);
    expect(bom.vulnerabilities.length).toBeGreaterThan(0);
  });

  it('rejects a document that is not CycloneDX 1.5', () => {
    expect(validateCycloneDx15(null).length).toBeGreaterThan(0);
    expect(validateCycloneDx15({ bomFormat: 'SPDX' }).length).toBeGreaterThan(0);
  });
});
