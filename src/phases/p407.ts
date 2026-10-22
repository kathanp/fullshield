/** Phase 407. SQL value holes to placeholders. Off unless FULLSHIELD_EXPERIMENTAL_SQLPARAM=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SQLPARAM';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type SqlHole = 'value' | 'identifier' | 'unknown' | 'statement';
export type SqlClient = 'pg' | 'mysql' | 'unknown';

export interface SqlRewrite {
  source: string;
  refused: boolean;
  message: string;
}

export function rewriteSql(source: string, hole: SqlHole, client: SqlClient): SqlRewrite {
  const same: SqlRewrite = { source, refused: true, message: '' };
  if (!enabled()) {
    return same;
  }
  if (hole === 'identifier') {
    return { source, refused: true, message: 'allowlist is required' };
  }
  if (hole !== 'value' || client === 'unknown' || source.includes(';')) {
    return { source, refused: true, message: 'refused' };
  }
  const match = /^(.*\.query\()'([^']*)'\s*\+\s*([A-Za-z0-9_.]+)\)$/.exec(source);
  if (match === null) {
    return { source, refused: true, message: 'refused' };
  }
  const placeholder = client === 'pg' ? '$1' : '?';
  const head = match[1] ?? '';
  const literal = match[2] ?? '';
  const expr = match[3] ?? '';
  return {
    source: `${head}'${literal}${placeholder}', [${expr}])`,
    refused: false,
    message: '',
  };
}
