import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

describe('Q8 recorded count', () => {
  it('matches the length of quality/baseline.json q8', () => {
    const baseline = JSON.parse(readFileSync('quality/baseline.json', 'utf8')) as { q8: string[] };
    const doc = readFileSync('docs/QUALITY.md', 'utf8');
    expect(doc).toContain(`${baseline.q8.length} existing literals recorded in quality/baseline.json`);
  });
});
