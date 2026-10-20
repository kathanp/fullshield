export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function advisoryIds(text: string): string[] {
  const found = new Set<string>();
  for (const match of text.matchAll(/GHSA-[0-9a-z-]+/gi)) {found.add(match[0].toUpperCase());}
  for (const match of text.matchAll(/CVE-\d{4}-\d+/gi)) {found.add(match[0].toUpperCase());}
  return [...found].sort();
}

export function firstCwe(...values: unknown[]): string | undefined {
  const found = new Set<string>();
  for (const value of values) {collectCwe(value, found);}
  return [...found].sort()[0];
}

function collectCwe(value: unknown, found: Set<string>): void {
  if (typeof value === 'string') {
    const match = /CWE-\d+/i.exec(value);
    if (match !== null) {found.add(match[0].toUpperCase());}
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {collectCwe(item, found);}
    return;
  }
  if (!isRecord(value)) {return;}
  if ('id' in value) {collectCwe(value.id, found);}
  if ('cwe' in value) {collectCwe(value.cwe, found);}
  if ('tags' in value) {collectCwe(value.tags, found);}
}

export function fingerprintValues(value: unknown): string[] {
  if (!isRecord(value)) {return [];}
  const out: string[] = [];
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string' && item.length > 0) {out.push(`${key}=${item}`);}
  }
  return out.sort();
}

export function normPath(file: string): string {
  const value = file.replace(/\\/g, '/');
  return value.startsWith('./') ? value.slice(2) : value;
}
