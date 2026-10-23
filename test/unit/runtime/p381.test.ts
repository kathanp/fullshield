import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { assertHooksMatchCatalog, enabled, FLAG, installCatalog, invokeHook, loadCatalog, type CatalogSink } from '../../../src/runtime/exp/p381.js';

const row: CatalogSink = { package: 'inert-db', member: 'query', argumentIndex: 0, class: 'sql' };

describe('phase 381 catalog hooks', () => {
  it('installs nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(installCatalog([row]).installed).toEqual([]);
  });

  it('installs a catalog row and blocks the corpus payload', () => {
    process.env[FLAG] = '1';
    const { installed } = installCatalog([row]);
    expect(installed).toHaveLength(1);
    expect(invokeHook(installed, 'inert-db', 'query', ["' OR '1"], 'block').action).toBe('block');
    expect(invokeHook(installed, 'inert-db', 'query', ['select 1'], 'block').action).toBe('allow');
  });

  it('uninstalls a row that was removed', () => {
    process.env[FLAG] = '1';
    const { installed } = installCatalog([]);
    expect(invokeHook(installed, 'inert-db', 'query', ["' OR '1"], 'block').action).toBe('allow');
  });

  it('logs an unknown class once and rejects a hand-written hook', () => {
    process.env[FLAG] = '1';
    const { installed, log } = installCatalog([
      { package: 'x', member: 'y', argumentIndex: 0, class: 'not-a-class' },
      { package: 'x', member: 'z', argumentIndex: 0, class: 'not-a-class' },
    ]);
    expect(installed).toEqual([]);
    expect(log).toEqual(['unknown catalog class not-a-class']);
    expect(() => assertHooksMatchCatalog(['hand.written'], [row])).toThrow(/not a catalog row/);
  });

  it('does not import the scanner or node:sqlite', () => {
    const source = readFileSync(new URL('../../../src/runtime/exp/p381.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('src/modules');
    expect(source).not.toContain('src/engine');
    expect(source).not.toContain('src/phases');
    expect(source).not.toContain('src/core');
    expect(source).not.toContain('node:sqlite');
  });

  it('loads catalog JSON, skips a runtime gap, and monitors other payloads', () => {
    const dir = mkdtempSync(join(tmpdir(), 'p381-'));
    const path = join(dir, 'catalog.json');
    writeFileSync(path, JSON.stringify({ not: 'array' }));
    expect(loadCatalog(path)).toEqual([]);
    writeFileSync(path, JSON.stringify([
      row,
      { package: 'gap', member: 'skip', argumentIndex: 0, class: 'not-a-class', runtimeGap: true },
      { package: 'sh', member: 'exec', argumentIndex: 0, class: 'shell' },
    ]));
    process.env[FLAG] = '1';
    try {
      const loaded = loadCatalog(path);
      const { installed, log } = installCatalog(loaded);
      expect(installed.map((hook) => hook.member)).toEqual(['query', 'exec']);
      expect(log).toEqual([]);
      expect(invokeHook(installed, 'sh', 'exec', ['../etc/passwd'], 'monitor').action).toBe('monitor');
      expect(invokeHook(installed, 'inert-db', 'query', ['$where'], 'block').action).toBe('block');
      expect(invokeHook(installed, 'inert-db', 'query', [1], 'block').action).toBe('allow');
      expect(() => assertHooksMatchCatalog(['inert-db.query'], [row])).not.toThrow();
    } finally {
      delete process.env[FLAG];
    }
  });
});
