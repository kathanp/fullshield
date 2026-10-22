import { describe, expect, it } from 'vitest';

import { buildVex, DYNAMIC_IMPORT_FLAG, DYNAMIC_IMPORT_LIMIT, emitVex, enabled, FLAG, validateVex } from '../../../src/phases/p369.js';

const previous = '{"statements":[{"id":"FIXTURE-ADVISORY","status":"not_affected"}]}';

describe('phase 369 VEX evidence', () => {
  it('keeps the previous emitter bytes when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(emitVex([{ id: 'FIXTURE-ADVISORY', reachability: 'not-imported', witness: 'no import' }], previous)).toBe(previous);
  });

  it('emits not affected for not-imported and includes the dynamic-import limit when 232 is off', () => {
    process.env[FLAG] = '1';
    const document = buildVex([{ id: 'FIXTURE-NOT-IMPORTED', reachability: 'not-imported', witness: 'no static import' }]);
    expect(document.statements).toHaveLength(1);
    expect(document.statements[0]?.justification).toContain(DYNAMIC_IMPORT_LIMIT);
    expect(document.statements[0]?.justification).toContain('dynamic import');
    expect(validateVex(document)).toEqual([]);
    const roundTrip = JSON.parse(emitVex([{ id: 'FIXTURE-NOT-IMPORTED', reachability: 'not-imported', witness: 'no static import' }], previous)) as ReturnType<typeof buildVex>;
    expect(validateVex(roundTrip)).toEqual([]);
  });

  it('omits unknown from not affected and keeps it in the scan', () => {
    process.env[FLAG] = '1';
    const document = buildVex([{ id: 'FIXTURE-UNKNOWN', reachability: 'reachability-unknown', witness: 'maybe' }]);
    expect(document.statements).toEqual([]);
    expect(document.remainInScan).toEqual(['FIXTURE-UNKNOWN']);
  });

  it('does not mark a reachable advisory not affected', () => {
    process.env[FLAG] = '1';
    const document = buildVex([
      { id: 'FIXTURE-REACHABLE-DEP', reachability: 'function-reachable-via-dependency', witness: 'call' },
      { id: 'FIXTURE-REACHABLE', reachability: 'reachable', witness: 'import' },
    ]);
    expect(document.statements).toEqual([]);
    expect(document.remainInScan).toHaveLength(2);
  });

  it('drops the dynamic-import sentence when phase 232 is on', () => {
    process.env[FLAG] = '1';
    process.env[DYNAMIC_IMPORT_FLAG] = '1';
    const document = buildVex([{ id: 'FIXTURE-SYMBOL', reachability: 'symbol-not-called', witness: 'export unused' }]);
    expect(document.statements[0]?.justification).toBe('export unused');
    expect(document.statements[0]?.justification).not.toContain(DYNAMIC_IMPORT_LIMIT);
  });
});
