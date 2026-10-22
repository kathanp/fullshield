import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, rewriteSql } from '../../../src/phases/p407.js';

const value = "db.query('select * from t where id = ' + req.params.id)";
const order = 'ORDER BY ${req.query.sort}';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 407', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(rewriteSql(value, 'value', 'pg').source).toBe(value);
  });

  it('rewrites a value hole and refuses the other classes', () => {
    process.env[FLAG] = '1';
    const rewritten = rewriteSql(value, 'value', 'pg');
    expect(rewritten.refused).toBe(false);
    expect(rewritten.source).toContain('$1');
    expect(rewritten.source).toContain('req.params.id');
    expect(rewriteSql(order, 'identifier', 'pg')).toMatchObject({ source: order, message: 'allowlist is required' });
    expect(rewriteSql(value, 'value', 'unknown').refused).toBe(true);
    expect(rewriteSql('q; ${x}', 'value', 'mysql').source).toBe('q; ${x}');
  });
});
