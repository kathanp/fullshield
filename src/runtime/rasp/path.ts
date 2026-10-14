/** Logical path resolve (posix-style) so corpus checks are OS-independent. */
export function logicalResolve(p: string): string {
  const isAbs = p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p);
  const parts: string[] = [];
  for (const seg of p.split(/[\\/]+/)) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      parts.pop();
      continue;
    }
    parts.push(seg);
  }
  return (isAbs ? '/' : '') + parts.join('/');
}

function isInside(base: string, target: string): boolean {
  const b = logicalResolve(base).replace(/\/+$/, '');
  const t = logicalResolve(target);
  if (b === '') return !t.startsWith('/') && !t.split('/').includes('..');
  return t === b || t.startsWith(`${b}/`);
}

function inferBase(sink: string, input: string): string {
  const idx = sink.indexOf(input);
  if (idx <= 0) return '';
  return sink.slice(0, idx);
}

function lastSeg(p: string): string | undefined {
  const parts = logicalResolve(p).split('/').filter(Boolean);
  return parts[parts.length - 1];
}

export function pathInputEscapes(sink: string, input: string, base?: string): boolean {
  if (!input) return false;
  if (input.includes('\0') || sink.includes('\0')) return true;
  if (sink.includes(input)) {
    if (input.includes('..')) return true;
    const intended = base !== undefined && base.length > 0 ? base : inferBase(sink, input);
    if (intended === '') {
      return input.startsWith('/') || /^[A-Za-z]:[\\/]/.test(input) || input.includes('..');
    }
    return !isInside(intended, sink);
  }
  // path.join already resolved ".." so the raw input may no longer appear.
  // If the input is a traversal/absolute and its final segment is the sink file, it escaped.
  if (input.includes('..') || input.startsWith('/') || /^[A-Za-z]:[\\/]/.test(input)) {
    const a = lastSeg(input);
    const b = lastSeg(sink);
    if (a && a === b) return true;
  }
  return false;
}
