import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { importHref } from '../../../src/runtime/importHref.js';

const root = process.cwd();
const RUNTIME_ENTRIES = ['register.ts', 'auto.ts', 'express.ts', 'fastify.ts', 'index.ts'] as const;

describe('Phase 25 runtime import hygiene', () => {
  it('builds --import specifiers with pathToFileURL (Windows-safe)', () => {
    const abs = join(root, 'dist', 'runtime', 'register.js');
    const href = importHref(abs);
    expect(href).toBe(pathToFileURL(abs).href);
    expect(href.startsWith('file:')).toBe(true);
  });

  it('runtime entry sources do not import node:sqlite', () => {
    for (const name of RUNTIME_ENTRIES) {
      const text = readFileSync(join(root, 'src', 'runtime', name), 'utf8');
      expect(text, name).not.toMatch(/node:sqlite/);
    }
  });
});
