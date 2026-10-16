import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

describe('Phase 38 comparison', () => {
  it('keeps a class map and does not invent tool results', () => {
    const harness = readFileSync(join(process.cwd(), 'bench', 'compare.mjs'), 'utf8');
    expect(harness).toContain('CLASS_MAP');
    expect(harness).toContain('semgrep');
    expect(harness).toContain('osv-scanner');
    const comparison = readFileSync(join(process.cwd(), 'COMPARISON.md'), 'utf8');
    expect(comparison).toMatch(/not executed/i);
    expect(comparison).not.toMatch(/\b\d+\s+true positives\b/i);
  });
});