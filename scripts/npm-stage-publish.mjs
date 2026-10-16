#!/usr/bin/env node
/**
 * Stage fullshield via libnpmpublish so a 403 prints npm's {code,message}.
 * The CLI swallows that body (it only appends body.error).
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const PACKAGE = 'fullshield';
const REGISTRY = 'https://registry.npmjs.org';
const authKey = '//registry.npmjs.org/:_authToken';

function npmRoot() {
  const r = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr || 'npm root -g failed');
  return r.stdout.trim();
}

const require = createRequire(join(npmRoot(), 'npm/package.json'));
const libpub = require('libnpmpublish');

function mask(value) {
  if (value && process.env.GITHUB_ACTIONS === 'true') {
    console.log(`::add-mask::${value}`);
  }
}

async function npmToken() {
  let idToken = process.env.NPM_ID_TOKEN;
  if (!idToken) {
    const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    if (!requestUrl || !requestToken) {
      throw new Error('no NPM_ID_TOKEN or GitHub OIDC request env');
    }
    const oidcUrl = new URL(requestUrl);
    oidcUrl.searchParams.set('audience', 'npm:registry.npmjs.org');
    const oidcRes = await fetch(oidcUrl, {
      headers: { Authorization: `Bearer ${requestToken}`, Accept: 'application/json' },
    });
    const oidcJson = await oidcRes.json();
    idToken = oidcJson.value;
  }
  if (!idToken) throw new Error('failed to get GitHub OIDC token');
  mask(idToken);

  const ex = await fetch(`${REGISTRY}/-/npm/v1/oidc/token/exchange/package/${PACKAGE}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${idToken}`, Accept: 'application/json' },
  });
  const body = await ex.json();
  if (!ex.ok || !body.token) {
    throw new Error(`OIDC exchange HTTP ${ex.status}: ${JSON.stringify(body)}`);
  }
  mask(body.token);
  return body.token;
}

function packTarball(version) {
  const packed = spawnSync('npm', ['pack'], { encoding: 'utf8' });
  if (packed.status !== 0) {
    console.error(packed.stdout, packed.stderr);
    throw new Error('npm pack failed');
  }
  const name = `${PACKAGE}-${version}.tgz`;
  return { name, data: readFileSync(name) };
}

function printErr(label, err) {
  console.error(label);
  console.error('message:', err.message);
  console.error('code:', err.code);
  console.error('status:', err.statusCode);
  console.error('uri:', err.uri);
  console.error('body:', JSON.stringify(err.body, null, 2));
}

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const token = await npmToken();
const tarball = packTarball(pkg.version);

const baseOpts = {
  [authKey]: token,
  registry: `${REGISTRY}/`,
  access: 'public',
  defaultTag: 'latest',
  stage: true,
  command: 'stage',
};

async function stage(provenance) {
  return libpub.publish(pkg, tarball.data, { ...baseOpts, provenance });
}

try {
  try {
    const res = await stage(true);
    console.log(`staged ${PACKAGE}@${pkg.version} with provenance id=${res.stageId ?? 'unknown'}`);
  } catch (err) {
    printErr('stage with provenance failed', err);
    console.error(
      'refusing to stage without provenance. 0.1.3 was published that way after a sigstore 409 and must not repeat.',
    );
    process.exit(1);
  }
} finally {
  try {
    unlinkSync(tarball.name);
  } catch {
    // already gone
  }
}
