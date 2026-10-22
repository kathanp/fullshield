import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { analyzeExpress, enabled, FLAG } from '../../../src/phases/p291.js';

const SOURCE = `
function err(e, req, res, next) { res.send(e); }
app.set('query parser', 'extended');
app.get('/files/*splat', async (req, res) => { throw new Error('x'); });
app.get('/u/:id(\\\\d+)', (req, res) => { res.send(req.params.id); });
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 291 express 5', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeExpress(SOURCE, { version: '5.0.0' })).toEqual({ routes: [], events: [], findings: [] });
  });

  it('gives only express 5 the rejection edge and the compiled splat', () => {
    process.env[FLAG] = '1';
    const v5 = analyzeExpress(SOURCE, { version: '5.0.0' });
    const v4 = analyzeExpress(SOURCE, { version: '4.18.2' });
    expect(v5.routes[0]).toMatchObject({ splat: true, rejectionEdge: true, queryKeys: 'nested', fullPath: '/files/*splat' });
    expect(v5.routes[1]?.fullPath).toBeNull();
    expect(v5.events.map((event) => event.reason)).toContain('inline regex');
    expect(v4.routes[0]).toMatchObject({ splat: false, rejectionEdge: false, fullPath: '/files/*splat' });
    expect(v4.routes[1]?.fullPath).toContain('(');
    expect(v4.events).toEqual([]);
    const bare = 'function err(a, b, c, d) {}\napp.get("/a", async (req, res) => { throw new Error("x"); });';
    expect(analyzeExpress(bare, { version: '5.0.0' }).routes[0]?.queryKeys).toBe('flat');
    expect(analyzeExpress(bare, { version: '4.18.2' }).routes[0]?.queryKeys).toBe('nested');
  });

  it('keeps an unknown parser and stays quiet on clean-app', () => {
    process.env[FLAG] = '1';
    const custom = analyzeExpress("app.set('query parser', 'custom');\napp.get('/a', (req, res) => {});", { version: '5.0.0' });
    expect(custom.routes[0]?.queryKeys).toBe('unknown');
    expect(custom.events).toHaveLength(1);
    expect(custom.findings).toEqual([]);
    const root = join(import.meta.dirname, '../../..', 'test/fixtures/clean-app');
    const files = walk(root);
    for (const file of files) {
      expect(analyzeExpress(readFileSync(file, 'utf8'), { version: '4.18.2', file }).findings).toEqual([]);
    }
  });
});

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {out.push(...walk(full)); continue;}
    if (name.endsWith('.js')) {out.push(full);}
  }
  return out;
}
