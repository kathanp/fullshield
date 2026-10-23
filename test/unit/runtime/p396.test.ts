import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { applyFieldPatches, enabled, FLAG } from '../../../src/runtime/exp/p396.js';

describe('phase 396 field patches', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    const body = { role: 'admin', name: 'ada' };
    expect(applyFieldPatches(body, [{ path: 'body.role', action: 'strip' }]).body).toBe(body);
  });

  it('strips body.role and leaves body.name', () => {
    process.env[FLAG] = '1';
    const result = applyFieldPatches({ role: 'admin', name: 'ada' }, [{ path: 'body.role', action: 'strip' }]);
    expect(result.body).toEqual({ name: 'ada' });
    expect(result.status).toBe(200);
  });

  it('blocks with 403 and ignores an unknown path', () => {
    process.env[FLAG] = '1';
    expect(applyFieldPatches({ role: 'admin' }, [{ path: 'body.role' }]).status).toBe(403);
    const unknown = applyFieldPatches({ name: 'ada' }, [{ path: 'body.missing' }]);
    expect(unknown.status).not.toBe(403);
    expect(unknown.logs).toHaveLength(1);
    const twice = applyFieldPatches({ name: 'ada' }, [{ path: 'body.missing' }, { path: 'body.missing' }]);
    expect(twice.logs).toEqual(['unknown field path body.missing']);
    const nested = applyFieldPatches({ user: { role: 'admin', name: 'ada' } }, [{ path: 'user.role', action: 'strip' }]);
    expect(nested.body).toEqual({ user: { name: 'ada' } });
    expect(nested.status).toBe(200);
    expect(applyFieldPatches({ user: { role: 'admin' } }, [{ path: 'user.role' }]).status).toBe(403);
    expect(applyFieldPatches({ user: 'admin' }, [{ path: 'user.role', action: 'strip' }]).body).toEqual({ user: 'admin' });
    expect(applyFieldPatches({ role: 'admin' }, [{ path: 'body', action: 'strip' }]).body).toEqual({ role: 'admin' });
    expect(applyFieldPatches({ a: null }, [{ path: 'a.b' }]).logs).toEqual(['unknown field path a.b']);
  });

  it('does not write source files', () => {
    const source = readFileSync(new URL('../../../src/runtime/exp/p396.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('writeFile');
  });
});
