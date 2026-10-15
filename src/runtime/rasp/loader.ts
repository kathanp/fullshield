/**
 * ESM loader hook registered by `fullshield/runtime/register`.
 * Builtins other than sqlite are wrapped at enable time. `node:sqlite` is
 * wrapped only when the app actually loads it (via a callback installed by
 * the register bundle) so `--import` does not emit SQLite ExperimentalWarning.
 * It must never throw (fail-open).
 */
export async function load(
  url: string,
  context: unknown,
  nextLoad: (url: string, context: unknown) => Promise<unknown>,
): Promise<unknown> {
  const result = await nextLoad(url, context);
  if (typeof url === 'string' && (url === 'node:sqlite' || url.startsWith('node:sqlite'))) {
    try {
      const wrap = (globalThis as Record<symbol, (() => void) | undefined>)[
        Symbol.for('fullshield.rasp.wrapSqlite')
      ];
      wrap?.();
    } catch {
      // fail open
    }
  }
  return result;
}
