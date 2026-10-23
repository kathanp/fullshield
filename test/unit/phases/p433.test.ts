import { generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, signSbom, verifySbom } from '../../../src/phases/p433.js';

afterEach(() => {
  delete process.env[FLAG];
});

function ed25519Pem(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateExported = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicExported = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    privatePem: typeof privateExported === 'string' ? privateExported : privateExported.toString(),
    publicPem: typeof publicExported === 'string' ? publicExported : publicExported.toString(),
  };
}

const sbom = { bomFormat: 'CycloneDX', specVersion: '1.6' };
const repoRoot = join(tmpdir(), 'fullshield-p433-repo');
const insideKey = join(repoRoot, 'keys', 'dev.pem');
const outsideKey = join(tmpdir(), 'fullshield-p433-outside.pem');

describe('phase 433 SBOM signatures', () => {
  it('writes no signature when the flag is off', () => {
    expect(enabled()).toBe(false);
    const { privatePem } = ed25519Pem();
    const result = signSbom(sbom, privatePem, insideKey, repoRoot);
    expect(result).toEqual({ exitCode: 0, wrote: false, signature: null, warning: null, document: sbom });
    expect(JSON.stringify(result.document)).not.toContain('PRIVATE KEY');
  });

  it('signs the document and warns when the key path is inside the repo', () => {
    process.env[FLAG] = '1';
    const { privatePem, publicPem } = ed25519Pem();
    const result = signSbom(sbom, privatePem, insideKey, repoRoot);
    expect(result.exitCode).toBe(0);
    expect(result.wrote).toBe(true);
    expect(result.warning).toBe('warning: private key path is inside the repository');
    expect(result.document).toEqual(sbom);
    expect(result.document).not.toBe(sbom);
    expect(JSON.stringify(result.document)).not.toContain('PRIVATE KEY');
    expect(result.signature).toBeInstanceOf(Buffer);
    if (result.signature === null) {
      throw new Error('missing signature');
    }
    expect(verifySbom(result.document, result.signature, publicPem)).toBe(true);
  });

  it('exits FS-E without a key and rejects a tampered document', () => {
    process.env[FLAG] = '1';
    const missing = signSbom(sbom, null, outsideKey, repoRoot);
    expect(missing).toEqual({ exitCode: 1, code: 'FS-E', wrote: false, signature: null, warning: null, document: sbom });
    expect(signSbom(sbom, '', outsideKey, repoRoot).code).toBe('FS-E');
    const { privatePem, publicPem } = ed25519Pem();
    const signed = signSbom(sbom, privatePem, outsideKey, repoRoot);
    expect(signed.warning).toBeNull();
    expect(signed.signature).toBeInstanceOf(Buffer);
    if (signed.signature === null) {
      throw new Error('missing signature');
    }
    expect(verifySbom({ ...sbom, tampered: true }, signed.signature, publicPem)).toBe(false);
  });
});
