import type { OsvVuln } from './osv.js';

/** Named functions from advisory data. Empty when the advisory does not name any. */
export function affectedFunctionNames(vuln: OsvVuln): string[] {
  const names = new Set<string>();
  for (const affected of vuln.affected ?? []) {
    const list = affected.ecosystem_specific?.affected_functions;
    if (!Array.isArray(list)) {continue;}
    for (const item of list) {
      if (typeof item === 'string' && item.length > 0) {names.add(item);}
    }
  }
  return [...names];
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function called(source: string, local: string): boolean {
  return new RegExp(`\\b${escapeRegExp(local)}\\s*\\(`).test(source);
}

function memberCalled(source: string, object: string, member: string): boolean {
  return new RegExp(`\\b${escapeRegExp(object)}\\s*\\.\\s*${escapeRegExp(member)}\\s*\\(`).test(source);
}

/** True only when this file imports or requires `symbol` and then calls that binding. */
export function sourceCallsAffectedSymbol(source: string, symbol: string): boolean {
  const esc = escapeRegExp(symbol);
  const named = new RegExp(
    `import\\s*\\{([^}]+)\\}\\s*from\\s*['"][^'"]+['"]`,
    'g',
  );
  let match: RegExpExecArray | null;
  while ((match = named.exec(source)) !== null) {
    const parts = (match[1] ?? '').split(',');
    for (const part of parts) {
      const bits = part.trim().split(/\s+as\s+/);
      const imported = bits[0]?.trim();
      const local = (bits[1] ?? bits[0])?.trim();
      if (imported === symbol && local !== undefined && called(source, local)) {return true;}
    }
  }
  const star = /import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"][^'"]+['"]/g;
  while ((match = star.exec(source)) !== null) {
    const local = match[1];
    if (local !== undefined && memberCalled(source, local, symbol)) {return true;}
  }
  const subDefault = new RegExp(
    `import\\s+([A-Za-z_$][\\w$]*)\\s+from\\s+['"][^'"]+/${esc}['"]`,
  );
  const sub = subDefault.exec(source);
  if (sub?.[1] !== undefined && called(source, sub[1])) {return true;}

  const reqMember = new RegExp(
    `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\(\\s*['"][^'"]+['"]\\s*\\)\\s*\\.\\s*${esc}`,
  );
  const reqHit = reqMember.exec(source);
  if (reqHit?.[1] !== undefined && called(source, reqHit[1])) {return true;}

  const reqNs = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"][^'"]+['"]\s*\)/g;
  while ((match = reqNs.exec(source)) !== null) {
    const local = match[1];
    if (local !== undefined && memberCalled(source, local, symbol)) {return true;}
  }
  const reqNamed = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*['"][^'"]+['"]\s*\)/g;
  while ((match = reqNamed.exec(source)) !== null) {
    const parts = (match[1] ?? '').split(',');
    for (const part of parts) {
      const bits = part.trim().split(/\s*:\s*/);
      const imported = bits[0]?.trim();
      const local = (bits[1] ?? bits[0])?.trim();
      if (imported === symbol && local !== undefined && called(source, local)) {return true;}
    }
  }
  const reqSub = new RegExp(
    `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\(\\s*['"][^'"]+/${esc}['"]\\s*\\)`,
  );
  const subReq = reqSub.exec(source);
  if (subReq?.[1] !== undefined && called(source, subReq[1])) {return true;}

  const barrel = new RegExp(`export\\s*\\{([^}]+)\\}\\s*from\\s*['"][^'"]+['"]`, 'g');
  while ((match = barrel.exec(source)) !== null) {
    const parts = (match[1] ?? '').split(',');
    for (const part of parts) {
      const bits = part.trim().split(/\s+as\s+/);
      const exported = (bits[1] ?? bits[0])?.trim();
      if (exported === symbol) {
        const local = bits[0]?.trim();
        if (local !== undefined && called(source, local)) {return true;}
      }
    }
  }
  return false;
}

export function classifySymbolUse(
  symbols: readonly string[],
  sources: ReadonlyMap<string, string>,
): 'symbol-reachable' | 'symbol-not-called' {
  for (const symbol of symbols) {
    for (const source of sources.values()) {
      if (sourceCallsAffectedSymbol(source, symbol)) {return 'symbol-reachable';}
    }
  }
  return 'symbol-not-called';
}
