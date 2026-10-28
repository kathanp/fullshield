import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('Phase 552 stored speed claim', () => {
  it('bench/perf-v2.json is measured and README cites it without inventing Next.js times', async () => {
    const raw = JSON.parse(await readFile(join(root, 'bench', 'perf-v2.json'), 'utf8')) as {
      measured: boolean;
      label: string;
      apps: { next: { coldP50Seconds: number } };
      targets: { nextColdSeconds: number };
    };
    expect(raw.measured).toBe(true);
    expect(raw.label === 'reviewed' || raw.label === 'unreviewed').toBe(true);
    const readme = await readFile(join(root, 'README.md'), 'utf8');
    expect(readme).toContain('bench/perf-v2.json');
    const p50 = raw.apps.next.coldP50Seconds;
    const target = raw.targets.nextColdSeconds;
    if (p50 > target) {
      expect(readme).toMatch(/still (above|unmet|miss)|above the .*target|target is still unmet/i);
    }
    expect(readme).toContain(String(p50));
  });
});
