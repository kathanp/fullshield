export interface ShellToken {
  kind: 'word' | 'op' | 'space';
  start: number;
  end: number;
}

export function tokenizeShell(command: string): ShellToken[] {
  const tokens: ShellToken[] = [];
  let i = 0;
  const n = command.length;
  while (i < n) {
    const c = command[i]!;
    if (c === ' ' || c === '\t' || c === '\n') {
      const start = i;
      while (i < n && (command[i] === ' ' || command[i] === '\t' || command[i] === '\n')) i += 1;
      tokens.push({ kind: 'space', start, end: i });
      continue;
    }
    if (c === "'" || c === '"') {
      const quote = c;
      const start = i;
      i += 1;
      while (i < n && command[i] !== quote) {
        if (quote === '"' && command[i] === '\\') i += 1;
        i += 1;
      }
      if (i < n) i += 1;
      tokens.push({ kind: 'word', start, end: i });
      continue;
    }
    if (c === '`') {
      const start = i;
      i += 1;
      while (i < n && command[i] !== '`') i += 1;
      if (i < n) i += 1;
      tokens.push({ kind: 'op', start, end: i });
      continue;
    }
    if (c === '$' && (command[i + 1] === '(' || command[i + 1] === '{')) {
      const open = command[i + 1]!;
      const close = open === '(' ? ')' : '}';
      const start = i;
      i += 2;
      let depth = 1;
      while (i < n && depth > 0) {
        if (command[i] === open) depth += 1;
        else if (command[i] === close) depth -= 1;
        i += 1;
      }
      tokens.push({ kind: 'op', start, end: i });
      continue;
    }
    if (command.startsWith('||', i) || command.startsWith('&&', i) || command.startsWith('>>', i) || command.startsWith('<<', i)) {
      tokens.push({ kind: 'op', start: i, end: i + 2 });
      i += 2;
      continue;
    }
    if (';|&<>()'.includes(c)) {
      tokens.push({ kind: 'op', start: i, end: i + 1 });
      i += 1;
      continue;
    }
    const start = i;
    while (i < n && !/[\s;|&$`<>()]/.test(command[i]!)) i += 1;
    tokens.push({ kind: 'word', start, end: i });
  }
  return tokens;
}

export function shellInputChangesStructure(command: string, input: string): boolean {
  if (!input) return false;
  const tokens = tokenizeShell(command);
  let from = 0;
  while (from <= command.length) {
    const idx = command.indexOf(input, from);
    if (idx === -1) return false;
    const end = idx + input.length;
    const hit = tokens.filter((t) => t.kind !== 'space' && t.start < end && t.end > idx);
    if (!(hit.length === 1 && hit[0]!.kind === 'word' && hit[0]!.start <= idx && hit[0]!.end >= end)) {
      return true;
    }
    from = idx + Math.max(input.length, 1);
  }
  return false;
}
