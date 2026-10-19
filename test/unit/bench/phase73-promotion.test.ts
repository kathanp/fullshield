import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { writePromotionReports } from '../../../scripts/promotion-report.mjs';

describe('phase 73 promotion evidence', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('writes one report per flag and does not promote or scan holdouts', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-promotion-'));
    dirs.push(dir);
    const flags = writePromotionReports(dir);
    expect(flags).toHaveLength(4);
    const text = await readFile(join(dir, 'FULLSHIELD_EXPERIMENTAL_TAINT_V2.md'), 'utf8');
    expect(text).toContain('not promoted');
    expect(text).toContain('unmet — needs Phase 68 run after review');
    expect(text).not.toContain('reviewed: true');
  });
});
