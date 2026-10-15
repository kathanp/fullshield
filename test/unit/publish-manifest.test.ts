import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { manifestForRegistry } from '../../src/publish/manifest.js';

describe('manifestForRegistry', () => {
  it('attaches README.md text so the npm packument is not empty', () => {
    const readme = readFileSync(join(process.cwd(), 'README.md'), 'utf8');
    const manifest = manifestForRegistry({ name: 'fullshield', version: '0.1.2' }, readme);
    expect(manifest.readme).toBe(readme);
    expect(manifest.readme.length).toBeGreaterThan(100);
    expect(manifest.readme).toMatch(/^# FullShield/m);
    expect(manifest.readme).not.toBe('');
  });

  it('refuses a blank README so a staged package cannot publish an empty packument', () => {
    expect(() => manifestForRegistry({ name: 'fullshield' }, '')).toThrow(/README/);
    expect(() => manifestForRegistry({ name: 'fullshield' }, '   \n')).toThrow(/README/);
  });
});
