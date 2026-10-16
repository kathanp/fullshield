/**
 * Ask GitHub for a new OIDC token. Never reuse NPM_ID_TOKEN: the publish
 * probe used to save one, then verify ran longer than the token lifetime,
 * and the stage exchange returned HTTP 401.
 *
 * @param {Record<string, string | undefined>} env
 * @param {(url: URL, init: { headers: Record<string, string> }) => Promise<{ ok: boolean, status: number, json: () => Promise<{ value?: string } | null> }>} [fetchImpl]
 */
export async function githubOidcToken(env, fetchImpl = fetch) {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new Error('GitHub OIDC request env missing');
  }
  const oidcUrl = new URL(requestUrl);
  oidcUrl.searchParams.set('audience', 'npm:registry.npmjs.org');
  const oidcRes = await fetchImpl(oidcUrl, {
    headers: { Authorization: `Bearer ${requestToken}`, Accept: 'application/json' },
  });
  const oidcJson = await oidcRes.json();
  const idToken = oidcJson?.value;
  if (!oidcRes.ok || !idToken) {
    throw new Error(`GitHub OIDC token request failed ${oidcRes.status}`);
  }
  return idToken;
}
