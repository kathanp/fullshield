import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const FILES = ['dist/runtime/index.js', 'dist/runtime/express.js', 'dist/runtime/fastify.js'];

describe('runtime bundle (built)', () => {
  it('is under 50 KB and imports no scanner or parser', () => {
    let total = 0;
    for (const file of FILES) {
      const abs = join(root, file);
      total += statSync(abs).size;
      const text = readFileSync(abs, 'utf8');
      expect(text).not.toMatch(/typescript-estree|typescript-eslint|api\.osv\.dev|modules\/sast|modules\/deps/);
    }
    expect(total).toBeLessThan(50 * 1024);
  });
});
