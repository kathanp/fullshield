import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { BENCH_CLASSES } from '../../../src/bench/score.js';

const APPS = ['nodegoat', 'juice-shop', 'dvna'] as const;

describe('public bench ground truth', () => {
  it('marks every app unreviewed and cites an http(s) source per entry', () => {
    for (const app of APPS) {
      const path = join(process.cwd(), 'bench', app, 'ground-truth.json');
      const truth = JSON.parse(readFileSync(path, 'utf8')) as {
        reviewed: unknown;
        commit: string;
        entries: Array<{ class: string; file: string; line: number; description: string; source: string }>;
      };
      expect(truth.reviewed, `${app} must stay reviewed:false until a human flips it`).toBe(false);
      expect(truth.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(truth.entries.length).toBeGreaterThan(0);
      for (const entry of truth.entries) {
        expect(BENCH_CLASSES, `${app} ${entry.file}:${entry.line}`).toContain(entry.class);
        expect(entry.file.length).toBeGreaterThan(0);
        expect(entry.line).toBeGreaterThan(0);
        expect(entry.description.length).toBeGreaterThan(0);
        expect(entry.source).toMatch(/^https:\/\//);
      }
    }
  });
});
