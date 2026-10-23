import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase493-releasesign.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_RELEASESIGN = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_RELEASESIGN;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

const good = `name: Release
on: push
jobs:
  release:
    if: startsWith(github.ref, 'refs/tags/v')
    steps:
      - name: Sign SBOM
        run: node scripts/phase493-releasesign.mjs --sbom-sign
        env:
          FULLSHIELD_SBOM_KEY: \${{ secrets.SBOM_SIGN_KEY }}
  pull_request:
    if: github.event_name == 'pull_request'
    steps:
      - run: npm test
`;

describe('phase 493 release sign', () => {
  it('lints a fixture workflow and writes a dry-run signature', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs493-'));
    const workflow = join(dir, 'release.yml');
    writeFileSync(workflow, good);
    const lint = run(['--workflow', workflow], true);
    expect(lint.status).toBe(0);
    const { privateKey } = generateKeyPairSync('ed25519');
    const key = join(dir, 'key.pem');
    const sbom = join(dir, 'sbom.json');
    const out = join(dir, 'sbom.json.sig');
    writeFileSync(key, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(sbom, '{"bom":true}\n');
    const signed = run(['--key', key, '--sbom', sbom, '--out', out], true);
    expect(signed.status).toBe(0);
    expect(existsSync(out)).toBe(true);
    expect(readFileSync(out).length).toBeGreaterThan(0);
  });

  it('fails a release job missing the secret and continue-on-error, and allows a pull-request job', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs493b-'));
    const missing = join(dir, 'missing.yml');
    writeFileSync(missing, good.replace('          FULLSHIELD_SBOM_KEY: ${{ secrets.SBOM_SIGN_KEY }}\n', ''));
    const noSecret = run(['--workflow', missing], true);
    expect(noSecret.status).not.toBe(0);
    expect(noSecret.stderr).toContain('release job missing the secret');
    const pr = join(dir, 'pr.yml');
    writeFileSync(
      pr,
      `jobs:\n  pull_request:\n    if: github.event_name == 'pull_request'\n    steps:\n      - run: npm test\n`,
    );
    expect(run(['--workflow', pr], true).status).toBe(0);
    const skipped = join(dir, 'skip.yml');
    writeFileSync(skipped, good.replace('      - name: Sign SBOM\n', '      - name: Sign SBOM\n        continue-on-error: true\n'));
    const lint = run(['--workflow', skipped], true);
    expect(lint.status).not.toBe(0);
    expect(lint.stderr).toContain('continue-on-error fails the lint');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('npm publish')).toBe(false);
  });

  it('signs from the CI secret env and does not print the key', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs493c-'));
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const sbom = join(dir, 'sbom.json');
    const out = join(dir, 'sbom.json.sig');
    writeFileSync(sbom, '{"bom":true}\n');
    const env = { ...process.env, FULLSHIELD_EXPERIMENTAL_RELEASESIGN: '1', SBOM_SIGN_KEY: pem };
    const signed = spawnSync(process.execPath, [script, '--sbom-sign', '--sbom', sbom, '--out', out], {
      cwd: root,
      encoding: 'utf8',
      env,
    });
    expect(signed.status).toBe(0);
    expect(signed.stdout).toContain('signature written');
    expect(`${signed.stdout}${signed.stderr}`.includes('PRIVATE KEY')).toBe(false);
    expect(readFileSync(out).includes('PRIVATE KEY')).toBe(false);
    const missingEnv: NodeJS.ProcessEnv = { ...process.env, FULLSHIELD_EXPERIMENTAL_RELEASESIGN: '1' };
    delete missingEnv.SBOM_SIGN_KEY;
    const missing = spawnSync(process.execPath, [script, '--sbom-sign', '--sbom', sbom, '--out', out], {
      cwd: root,
      encoding: 'utf8',
      env: missingEnv,
    });
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain('release job missing the secret');
  });

  it('points the publish job at the sign command', () => {
    const publish = join(root, '.github', 'workflows', 'publish.yml');
    const lint = run(['--workflow', publish], true);
    expect(lint.status).toBe(0);
    const text = readFileSync(publish, 'utf8');
    expect(text).toContain('phase493-releasesign.mjs --sbom-sign');
    expect(text).toContain('secrets.SBOM_SIGN_KEY');
    expect(text.includes('continue-on-error: true')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--workflow', 'nope.yml'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
