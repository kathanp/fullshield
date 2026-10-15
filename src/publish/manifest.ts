/**
 * npm's CLI injects README.md into the registry manifest. libnpmpublish does
 * not: it sends package.json as-is, so the packument `readme` stays "".
 */
export function manifestForRegistry<T extends Record<string, unknown>>(
  pkg: T,
  readme: string,
): T & { readme: string } {
  if (readme.trim() === '') {
    throw new Error('README.md is empty; refusing to publish a blank packument readme');
  }
  return { ...pkg, readme };
}
