import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

describe('3.7.0 Swig extends taint', () => {
  it('flags a tainted local in the extended parent and leaves a static local quiet', async () => {
    const result = await scan({
      cwd: join(import.meta.dirname, '../../../fixtures/swig-extends-app'),
      modules: ['sast'],
      offline: true,
    });
    const lines = result.findings
      .filter((finding) => finding.ruleId === 'SAST-XSS-001')
      .map((finding) => `${finding.file?.split('/').pop()}:${finding.line}`);
    expect(lines).toContain('layout.html:1');
    expect(lines).not.toContain('layout.html:2');
  });
});
