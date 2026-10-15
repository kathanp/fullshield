import type { Finding } from '../../core/finding.js';
import type { SecretHit } from './types.js';

export type VerifyStatus = 'live' | 'revoked' | 'unknown';

export interface VerifyOptions {
  fetchImpl?: typeof fetch;
}

const AWS_URL = 'https://sts.amazonaws.com/';
const GITHUB_URL = 'https://api.github.com/user';
const STRIPE_URL = 'https://api.stripe.com/v1/balance';
const SLACK_URL = 'https://slack.com/api/auth.test';

function classifyHttp(status: number): VerifyStatus {
  if (status === 200) return 'live';
  if (status === 401 || status === 403) return 'revoked';
  return 'unknown';
}

async function call(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
): Promise<{ status: number; json?: unknown }> {
  const res = await fetchImpl(url, {
    ...init,
    redirect: 'error',
    signal: init.signal ?? AbortSignal.timeout(8000),
  });
  let json: unknown;
  try {
    json = await res.json();
  } catch {
    try {
      await res.text();
    } catch {
      // ignore body errors; never log
    }
  }
  return { status: res.status, json };
}

async function verifyAws(secret: string, fetchImpl: typeof fetch): Promise<VerifyStatus> {
  try {
    const { status } = await call(fetchImpl, AWS_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Amz-Access-Key-Id': secret,
      },
      body: 'Action=GetCallerIdentity&Version=2011-06-15',
    });
    if (status === 200) return 'live';
    if (status === 401) return 'revoked';
    return 'unknown';
  } catch {
    return 'unknown';
  }
}

async function verifyGithub(secret: string, fetchImpl: typeof fetch): Promise<VerifyStatus> {
  try {
    const { status } = await call(fetchImpl, GITHUB_URL, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${secret}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'fullshield',
      },
    });
    return classifyHttp(status);
  } catch {
    return 'unknown';
  }
}

async function verifyStripe(secret: string, fetchImpl: typeof fetch): Promise<VerifyStatus> {
  try {
    const { status } = await call(fetchImpl, STRIPE_URL, {
      method: 'GET',
      headers: { Authorization: `Bearer ${secret}` },
    });
    return classifyHttp(status);
  } catch {
    return 'unknown';
  }
}

async function verifySlack(secret: string, fetchImpl: typeof fetch): Promise<VerifyStatus> {
  try {
    const { status, json } = await call(fetchImpl, SLACK_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${secret}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: '',
    });
    if (status !== 200) return classifyHttp(status);
    if (typeof json === 'object' && json !== null && 'ok' in json) {
      return json.ok === true ? 'live' : 'revoked';
    }
    return 'unknown';
  } catch {
    return 'unknown';
  }
}

function providerFor(ruleId: string, secret: string): ((s: string, f: typeof fetch) => Promise<VerifyStatus>) | undefined {
  if (ruleId === 'SECRET-AWS-001' || secret.startsWith('AKIA')) return verifyAws;
  if (ruleId === 'SECRET-GITHUB-001' || /^(?:ghp|gho|ghu|ghs|ghr)_/.test(secret)) return verifyGithub;
  if (ruleId === 'SECRET-STRIPE-001' || /^sk_(?:live|test)_/.test(secret)) return verifyStripe;
  if (ruleId === 'SECRET-SLACK-001' || /^xox[baprs]-/.test(secret)) return verifySlack;
  return undefined;
}

/** Read-only identity checks. Never logs the key. */
export async function verifySecretHits(
  hits: readonly SecretHit[],
  options: VerifyOptions = {},
): Promise<SecretHit[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const out: SecretHit[] = [];
  for (const hit of hits) {
    const secret = hit.secret;
    if (secret === undefined || secret.length === 0) {
      out.push({ finding: { ...hit.finding, verification: 'unknown' }, secret: hit.secret });
      continue;
    }
    const run = providerFor(hit.finding.ruleId, secret);
    const verification = run === undefined ? 'unknown' : await run(secret, fetchImpl);
    out.push({ finding: { ...hit.finding, verification }, secret: hit.secret });
  }
  return out;
}

export async function applyVerification(
  findings: readonly Finding[],
  secretById: ReadonlyMap<string, string>,
  options: VerifyOptions = {},
): Promise<Finding[]> {
  const hits: SecretHit[] = findings
    .filter((f) => f.module === 'secrets')
    .map((finding) => ({ finding, secret: secretById.get(finding.id) }));
  const verified = await verifySecretHits(hits, options);
  const byId = new Map(verified.map((h) => [h.finding.id, h.finding]));
  return findings.map((f) => byId.get(f.id) ?? f);
}
