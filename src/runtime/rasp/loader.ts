/**
 * ESM loader hook registered by `fullshield/runtime/register`.
 * Builtins are wrapped at enable time; this hook is required so `--import`
 * uses `module.register` as specified. It must never throw (fail-open).
 */
export async function load(
  url: string,
  context: unknown,
  nextLoad: (url: string, context: unknown) => Promise<unknown>,
): Promise<unknown> {
  return nextLoad(url, context);
}
