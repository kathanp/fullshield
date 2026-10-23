/**
 * Phase 433. Local signatures for SBOM and VEX.
 * Off unless FULLSHIELD_EXPERIMENTAL_SBOMIGN=1.
 * Flag off: no signature is written.
 * The private key is never copied into the SBOM. A missing key exits FS-E.
 */
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { relative, resolve, sep } from 'node:path';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SBOMIGN';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SignResult {
  exitCode: number;
  code?: 'FS-E';
  wrote: boolean;
  signature: Buffer | null;
  warning: string | null;
  document: Record<string, unknown>;
}

function insideRepo(keyPath: string, repoRoot: string): boolean {
  const abs = resolve(repoRoot, keyPath);
  const root = resolve(repoRoot);
  const rel = relative(root, abs);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !rel.startsWith('..'));
}

export function signSbom(sbom: Record<string, unknown>, privatePem: string | null, keyPath: string, repoRoot: string): SignResult {
  const document = { ...sbom };
  if (!enabled()) {
    return { exitCode: 0, wrote: false, signature: null, warning: null, document };
  }
  if (privatePem === null || privatePem.length === 0) {
    return { exitCode: 1, code: 'FS-E', wrote: false, signature: null, warning: null, document };
  }
  const signature = sign(null, Buffer.from(JSON.stringify(document)), createPrivateKey(privatePem));
  const warning = insideRepo(keyPath, repoRoot) ? 'warning: private key path is inside the repository' : null;
  return { exitCode: 0, wrote: true, signature, warning, document };
}

export function verifySbom(document: Record<string, unknown>, signature: Buffer, publicPem: string): boolean {
  return verify(null, Buffer.from(JSON.stringify(document)), createPublicKey(publicPem), signature);
}
