/** Phase 409. Path prefix guard. Off unless FULLSHIELD_EXPERIMENTAL_PATHGUARD=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PATHGUARD';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function pathGuard(
  source: string,
  base: 'literal' | 'request',
  segment: 'multi' | 'filename',
): { source: string; refused: boolean } {
  if (!enabled() || base !== 'literal') {
    return { source, refused: true };
  }
  if (segment === 'filename') {
    return {
      source: source.replace('req.file.originalname', 'path.basename(req.file.originalname)'),
      refused: false,
    };
  }
  const guard = "if (!resolved.startsWith(root + path.sep) && resolved !== root) { throw new Error('path'); }";
  return { source: `${source}\n${guard}`, refused: false };
}
