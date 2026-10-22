/** Phase 257. A number, boolean, or literal union drops string-injection labels. `any` does not. */
export const IRTYPES_FLAG = 'FULLSHIELD_EXPERIMENTAL_IRTYPES';

export function irTypesEnabled(): boolean {
  return process.env[IRTYPES_FLAG] === '1';
}

const STRING_SINKS = new Set(['sqli', 'nosqli', 'cmdi', 'path', 'xss', 'ssrf', 'redirect', 'eval', 'ssti', 'log']);

export interface TypedValue {
  name: string;
  typeName: string;
}

/** `number`, `boolean`, and literal unions drop string-injection labels. `any` and `string` do not. */
export function dropsStringInjection(typeName: string): boolean {
  const text = typeName.replace(/\s/g, '');
  if (text === 'any' || text === 'string' || text === 'unknown') {return false;}
  if (text === 'number' || text === 'boolean') {return true;}
  if (/^(?:'[^']*'|"[^"]*")(?:\|(?:'[^']*'|"[^"]*"))+$/.test(text)) {return true;}
  return false;
}

export function sqlFindingForType(typeName: string, sink: string): boolean {
  if (!irTypesEnabled()) {return false;}
  if (!STRING_SINKS.has(sink)) {return false;}
  return !dropsStringInjection(typeName);
}

/** Resolves to the implementing class only when there is exactly one. */
export function resolveImplementor(impls: readonly { iface: string; method: string; className: string }[], iface: string, method: string): string | undefined {
  const hits = impls.filter((row) => row.iface === iface && row.method === method);
  return hits.length === 1 ? hits[0]?.className : undefined;
}
