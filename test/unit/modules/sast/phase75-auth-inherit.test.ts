import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const root = join(import.meta.dirname, '../../../fixtures');

describe('phase 75 router-level auth', () => {
  it('keeps a route flagged when auth is mounted after it, and clears router-level and prefixed mounts', async () => {
    const result = await scan({ cwd: join(root, 'auth-inherit-app'), modules: ['sast'], offline: true });
    const auth = result.findings.filter((finding) => finding.ruleId === 'SAST-AUTH-001');
    expect(auth.some((finding) => finding.file === 'src/late.js')).toBe(true);
    expect(auth.some((finding) => finding.file === 'src/early.js')).toBe(false);
    expect(auth.some((finding) => finding.file === 'src/api.js')).toBe(false);
  });
});
