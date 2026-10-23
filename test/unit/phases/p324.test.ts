import { afterEach, describe, expect, it } from 'vitest';

import { enabled, enumFindings, FLAG, RULE, type EnumHandler } from '../../../src/phases/p324.js';

function handler(over: Partial<EnumHandler> = {}): EnumHandler {
  return {
    file: 'reset.js',
    line: 2,
    kind: 'reset',
    unknownUser: { status: 200, literal: 'ok' },
    knownUser: { status: 200, literal: 'ok' },
    wrongPassword: { status: 401, literal: 'bad password' },
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 324 enumeration', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(enumFindings([handler({ unknownUser: { status: 404, literal: 'missing' } })])).toEqual([]);
  });

  it('reports 404 versus 200 and ignores matching literals', () => {
    process.env[FLAG] = '1';
    const diff = enumFindings([handler({ unknownUser: { status: 404, literal: 'missing' }, knownUser: { status: 200, literal: 'sent' } })]);
    expect(diff[0]?.ruleId).toBe(RULE);
    expect(diff[0]?.severity).toBe('low');
    expect(enumFindings([handler()])).toEqual([]);
  });

  it('marks a log-only difference as info and skips an email echo and the password arm', () => {
    process.env[FLAG] = '1';
    const log = enumFindings([
      handler({
        unknownUser: { status: 200, literal: 'ok', logOnly: true },
        knownUser: { status: 200, literal: 'sent', logOnly: true },
      }),
    ]);
    expect(log[0]?.severity).toBe('info');
    expect(enumFindings([handler({ unknownUser: { status: 404, literal: 'user.email', echoesEmail: true } })])).toEqual([]);
    expect(enumFindings([handler({ wrongPassword: { status: 500, literal: 'nope' } })])).toEqual([]);
  });
});
