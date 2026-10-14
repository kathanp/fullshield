export interface SqlToken {
  kind: 'string' | 'number' | 'comment' | 'ident' | 'op' | 'space';
  start: number;
  end: number;
}

export function tokenizeSql(sql: string): SqlToken[] {
  const tokens: SqlToken[] = [];
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i]!;
    if (c <= ' ') {
      const start = i;
      while (i < n && sql[i]! <= ' ') i += 1;
      tokens.push({ kind: 'space', start, end: i });
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      const start = i;
      i += 1;
      while (i < n) {
        if (sql[i] === quote) {
          if (sql[i + 1] === quote) {
            i += 2;
            continue;
          }
          i += 1;
          break;
        }
        i += 1;
      }
      tokens.push({ kind: 'string', start, end: i });
      continue;
    }
    if (c === '-' && sql[i + 1] === '-') {
      const start = i;
      i += 2;
      while (i < n && sql[i] !== '\n') i += 1;
      tokens.push({ kind: 'comment', start, end: i });
      continue;
    }
    if (c === '/' && sql[i + 1] === '*') {
      const start = i;
      i += 2;
      while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i += 1;
      if (i + 1 < n) i += 2;
      tokens.push({ kind: 'comment', start, end: i });
      continue;
    }
    if (c === '#') {
      const start = i;
      while (i < n && sql[i] !== '\n') i += 1;
      tokens.push({ kind: 'comment', start, end: i });
      continue;
    }
    if ((c >= '0' && c <= '9') || (c === '.' && i + 1 < n && sql[i + 1]! >= '0' && sql[i + 1]! <= '9')) {
      const start = i;
      while (i < n && /[0-9.eE+-]/.test(sql[i]!)) i += 1;
      tokens.push({ kind: 'number', start, end: i });
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const start = i;
      while (i < n && /[A-Za-z0-9_$]/.test(sql[i]!)) i += 1;
      tokens.push({ kind: 'ident', start, end: i });
      continue;
    }
    const start = i;
    if (
      sql.startsWith('<=', i) ||
      sql.startsWith('>=', i) ||
      sql.startsWith('<>', i) ||
      sql.startsWith('!=', i) ||
      sql.startsWith('||', i) ||
      sql.startsWith('&&', i)
    ) {
      i += 2;
    } else {
      i += 1;
    }
    tokens.push({ kind: 'op', start, end: i });
  }
  return tokens;
}

function spanUnsafe(tokens: SqlToken[], start: number, end: number): boolean {
  const hit = tokens.filter((t) => t.kind !== 'space' && t.start < end && t.end > start);
  if (hit.length === 1) {
    const t = hit[0]!;
    const safe = t.kind === 'string' || t.kind === 'number' || t.kind === 'comment';
    return !safe || t.start > start || t.end < end;
  }
  return hit.length > 0;
}

/** True when `input` appears in `query` and is not wholly one string/number/comment token. */
export function sqlInputChangesStructure(query: string, input: string): boolean {
  if (!input) return false;
  const tokens = tokenizeSql(query);
  let from = 0;
  while (from <= query.length) {
    const idx = query.indexOf(input, from);
    if (idx === -1) return false;
    if (spanUnsafe(tokens, idx, idx + input.length)) return true;
    from = idx + Math.max(input.length, 1);
  }
  return false;
}
