export function egressAllowed(host: string, allow: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.+$/, '');
  for (const rule of allow) {
    const r = rule.toLowerCase();
    if (r.startsWith('*.')) {
      const suffix = r.slice(1);
      if (h.endsWith(suffix) || h === r.slice(2)) return true;
    } else if (h === r) {
      return true;
    }
  }
  return false;
}
