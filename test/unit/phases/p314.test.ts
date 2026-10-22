import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, ownerCell, type AccessQuery, type ModelOwner } from '../../../src/phases/p314.js';

const model: ModelOwner = { ownerField: 'accountOwner', understood: true };

function query(over: Partial<AccessQuery> = {}): AccessQuery {
  return {
    filterKeys: ['accountOwner'],
    origins: { accountOwner: 'principal' },
    flow: 'same-variable',
    mustAliasOn: false,
    lookupOrigin: 'principal',
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 314 ownership flow', () => {
  it('stores no cell when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(ownerCell(query(), model)).toBeUndefined();
  });

  it('marks a principal filter as owner-scoped', () => {
    process.env[FLAG] = '1';
    expect(ownerCell(query(), model)).toBe('owner-scoped');
  });

  it('marks a finite request id filter as not-scoped', () => {
    process.env[FLAG] = '1';
    expect(
      ownerCell(
        query({ filterKeys: ['id'], origins: { id: 'request' }, lookupOrigin: 'request' }),
        model,
      ),
    ).toBe('not-scoped');
  });

  it('does not store an unresolved alias as not-scoped', () => {
    process.env[FLAG] = '1';
    const cell = ownerCell(query({ filterKeys: 'unresolved', flow: 'may-alias' }), model);
    expect(cell).toBe('unknown');
  });
});
