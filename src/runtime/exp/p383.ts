/**
 * Phase 383. SQL tokenizers at the hook.
 * Off unless FULLSHIELD_EXPERIMENTAL_SQLTOK=1.
 * One vector table, two runners. The lexer is a small interpreter, not a native module.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SQLTOK';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const DIALECTS = ['pg', 'mysql2', 'sqlite', 'mssql'] as const;
export type SqlDialect = (typeof DIALECTS)[number] | 'generic';

export interface SqlVector {
  id: string;
  dialect: string;
  /** SQL before the hole. A trailing quote means the hole starts inside a literal. */
  before: string;
  hole: string;
  bound: boolean;
  digits: boolean;
  expectEvent: boolean;
}

export const SQL_VECTORS: readonly SqlVector[] = [
  { id: 'breakout', dialect: 'pg', before: "select * from t where name = '", hole: "' OR '1", bound: false, digits: false, expectEvent: true },
  { id: 'bound', dialect: 'pg', before: 'select * from t where id = $1', hole: "' OR '1", bound: true, digits: false, expectEvent: false },
  { id: 'benign-pg', dialect: 'pg', before: "select * from t where name = '", hole: 'ada', bound: false, digits: false, expectEvent: false },
  { id: 'benign-mysql2', dialect: 'mysql2', before: "select * from t where name = '", hole: 'ada', bound: false, digits: false, expectEvent: false },
  { id: 'benign-sqlite', dialect: 'sqlite', before: "select * from t where name = '", hole: 'ada', bound: false, digits: false, expectEvent: false },
  { id: 'benign-mssql', dialect: 'mssql', before: "select * from t where name = '", hole: 'ada', bound: false, digits: false, expectEvent: false },
  { id: 'digits', dialect: 'pg', before: 'select * from t where id = ', hole: '15', bound: false, digits: true, expectEvent: false },
];

export interface SqlDecision {
  event: boolean;
  dialectUsed: SqlDialect;
  missingDialect: string | null;
}

function quoteOf(dialect: SqlDialect): "'" {
  return dialect === 'mssql' ? "'" : "'";
}

/** True when `before` ends inside a string literal. */
function insideLiteral(before: string, dialect: SqlDialect): boolean {
  const quote = quoteOf(dialect);
  let open = false;
  for (let i = 0; i < before.length; i += 1) {
    const char = before[i];
    if (char === quote) {
      const next = before[i + 1];
      if (open && next === quote) {
        i += 1;
        continue;
      }
      open = !open;
    }
  }
  return open;
}

export function classifySql(vector: Pick<SqlVector, 'dialect' | 'before' | 'hole' | 'bound' | 'digits'>): SqlDecision {
  const known = DIALECTS.includes(vector.dialect as (typeof DIALECTS)[number]);
  const dialectUsed: SqlDialect = known ? (vector.dialect as SqlDialect) : 'generic';
  const missingDialect = known ? null : vector.dialect;
  if (vector.bound) {
    return { event: false, dialectUsed, missingDialect };
  }
  if (vector.digits && /^[0-9]+$/.test(vector.hole)) {
    return { event: false, dialectUsed, missingDialect };
  }
  const open = insideLiteral(vector.before, dialectUsed);
  if (!open) {
    return { event: true, dialectUsed, missingDialect };
  }
  const quote = quoteOf(dialectUsed);
  const closedEarly = vector.hole.includes(quote);
  return { event: closedEarly, dialectUsed, missingDialect };
}

export function staticRunner(vector: SqlVector): SqlDecision {
  return classifySql(vector);
}

export function runtimeRunner(vector: SqlVector): SqlDecision {
  if (!enabled()) {
    return { event: false, dialectUsed: 'generic', missingDialect: null };
  }
  return classifySql(vector);
}
