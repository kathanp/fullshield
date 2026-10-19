import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const root = join(import.meta.dirname, '../../../fixtures');

describe('phase 50 template-engine XSS', () => {
  it('flags swig mustache and stays quiet for handlebars and unknown html', async () => {
    const swig = await scan({ cwd: join(root, 'swig-app'), modules: ['sast'], offline: true });
    expect(swig.findings.some((finding) => finding.ruleId === 'SAST-XSS-001' && finding.file?.endsWith('.swig'))).toBe(
      true,
    );
    const hbs = await scan({ cwd: join(root, 'hbs-app'), modules: ['sast'], offline: true });
    expect(hbs.findings.some((finding) => finding.ruleId === 'SAST-XSS-001')).toBe(false);
    const html = await scan({ cwd: join(root, 'html-app'), modules: ['sast'], offline: true });
    expect(html.findings.some((finding) => finding.ruleId === 'SAST-XSS-001')).toBe(false);
    const cons = await scan({ cwd: join(root, 'cons-swig-app'), modules: ['sast'], offline: true });
    expect(cons.findings.some((finding) => finding.ruleId === 'SAST-XSS-001' && finding.file?.endsWith('.html'))).toBe(
      true,
    );
    const other = await scan({ cwd: join(root, 'cons-other-app'), modules: ['sast'], offline: true });
    expect(other.findings.some((finding) => finding.ruleId === 'SAST-XSS-001')).toBe(false);
  });
});
