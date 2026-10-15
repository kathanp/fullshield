#!/usr/bin/env node
/**
 * Print the npm trusted-publisher handshake that `npm publish` hides.
 * Does not publish. Tokens are masked and never logged.
 */
const PACKAGE = 'fullshield';
const REGISTRY = 'https://registry.npmjs.org';
const CLAIMS = [
  'sub',
  'aud',
  'iss',
  'ref',
  'ref_type',
  'sha',
  'repository',
  'repository_id',
  'repository_owner',
  'repository_owner_id',
  'repository_visibility',
  'run_id',
  'actor',
  'workflow',
  'workflow_ref',
  'job_workflow_ref',
  'event_name',
  'environment',
];

function mask(value) {
  if (value && process.env.GITHUB_ACTIONS === 'true') {
    console.log(`::add-mask::${value}`);
  }
}

function decodeJwtPayload(jwt) {
  const payload = jwt.split('.')[1];
  if (!payload) throw new Error('OIDC token missing payload');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function pickClaims(payload) {
  const out = {};
  for (const key of CLAIMS) out[key] = payload[key] ?? null;
  return out;
}

async function readJson(res) {
  const text = await res.text();
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

function withoutToken(json) {
  if (!json || typeof json !== 'object') return json;
  const rest = { ...json };
  delete rest.token;
  return rest;
}

const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
if (!requestUrl || !requestToken) {
  console.error('ACTIONS_ID_TOKEN_REQUEST_URL / TOKEN missing (need id-token: write)');
  process.exit(1);
}

const oidcUrl = new URL(requestUrl);
oidcUrl.searchParams.set('audience', 'npm:registry.npmjs.org');

const oidcRes = await fetch(oidcUrl, {
  headers: { Authorization: `Bearer ${requestToken}`, Accept: 'application/json' },
});
const oidcBody = await readJson(oidcRes);
const idToken = oidcBody.json?.value;
if (!oidcRes.ok || !idToken) {
  console.error('GitHub OIDC token request failed', oidcRes.status, oidcBody.text.slice(0, 500));
  process.exit(1);
}
mask(idToken);

const claims = pickClaims(decodeJwtPayload(idToken));
console.log('GitHub OIDC claims npm will match:');
console.log(JSON.stringify(claims, null, 2));

const exchangeUrl = `${REGISTRY}/-/npm/v1/oidc/token/exchange/package/${PACKAGE}`;
const exchangeRes = await fetch(exchangeUrl, {
  method: 'POST',
  headers: { Authorization: `Bearer ${idToken}`, Accept: 'application/json' },
});
const exchangeBody = await readJson(exchangeRes);
if (exchangeBody.json?.token) mask(exchangeBody.json.token);
console.log(`OIDC exchange HTTP ${exchangeRes.status}`);
console.log(JSON.stringify(withoutToken(exchangeBody.json) ?? exchangeBody.text.slice(0, 1000), null, 2));

if (!exchangeRes.ok || !exchangeBody.json?.token) {
  console.error('OIDC token exchange failed — trusted publisher does not match this workflow identity.');
  process.exit(1);
}

if (process.env.GITHUB_ENV) {
  const { appendFileSync } = await import('node:fs');
  appendFileSync(process.env.GITHUB_ENV, `NPM_ID_TOKEN=${idToken}\n`);
}

const npmToken = exchangeBody.json.token;
const auth = { Authorization: `Bearer ${npmToken}`, Accept: 'application/json' };

const whoamiRes = await fetch(`${REGISTRY}/-/whoami`, { headers: auth });
const whoami = await readJson(whoamiRes);
console.log(`whoami HTTP ${whoamiRes.status}: ${whoami.text.slice(0, 300)}`);

const visRes = await fetch(`${REGISTRY}/-/package/${PACKAGE}/visibility`, { headers: auth });
const vis = await readJson(visRes);
console.log(`visibility HTTP ${visRes.status}: ${vis.text.slice(0, 300)}`);

const stageRes = await fetch(`${REGISTRY}/-/stage/package/${PACKAGE}`, {
  method: 'POST',
  headers: { ...auth, 'Content-Type': 'application/json' },
  body: '{}',
});
const stage = await readJson(stageRes);
console.log(`stage probe HTTP ${stageRes.status}`);
console.log(JSON.stringify(stage.json ?? stage.text.slice(0, 1000), null, 2));
