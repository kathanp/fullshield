/**
 * A declared license string from package data.
 * Arrays are omitted: SPDX needs one expression, and joining with AND or OR would invent one.
 */
export function licenseText(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === 'object' && value !== null && !Array.isArray(value) && 'type' in value) {
    const type = (value as { type?: unknown }).type;
    if (typeof type === 'string' && type.trim().length > 0) {return type.trim();}
  }
  return undefined;
}
