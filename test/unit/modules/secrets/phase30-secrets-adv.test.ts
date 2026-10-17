import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { writeBaseline } from '../../../../src/core/baseline.js';
import { scan } from '../../../../src/core/engine.js';
import { renderConsoleReport } from '../../../../src/reporters/console.js';
import { renderJsonReport } from '../../../../src/reporters/json.js';
import { secretsAdvEnabled } from '../../../../src/modules/secrets/experimental.js';
import { scanBundle } from '../../../../src/modules/secrets/bundle.js';
import { scanGitHistory } from '../../../../src/modules/secrets/history.js';
import {
  applyVerification,
  verifySecretHits,
  type VerifyStatus,
} from '../../../../src/modules/secrets/verify.js';
import type { SecretHit } from '../../../../src/modules/secrets/types.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV';
const PHASE30_ONLY_IDS = ['SECRET-BUNDLE-001'] as const;
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const bundleApp = join(process.cwd(), 'test', 'fixtures', 'secrets-bundle');
const bundleClean = join(process.cwd(), 'test', 'fixtures', 'secrets-bundle-clean');

const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
const STRIPE_KEY = 'sk_live_' + 'FAKEfakeFAKEfakeFAKE1234';
const GITHUB_TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const SLACK_TOKEN = 'xoxb-' + '123456789012-abcdefghijklmnop';

let dir: string;
const dirs: string[] = [];

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' }).trim();
}

async function initRepo(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-hist-'));
  dirs.push(cwd);
  git(cwd, 'init', '--quiet');
  git(cwd, 'config', 'user.email', 'test@example.com');
  git(cwd, 'config', 'user.name', 'Test');
  git(cwd, 'config', 'commit.gpgsign', 'false');
  git(cwd, 'config', 'core.autocrlf', 'false');
  return cwd;
}

beforeEach(() => {
  process.env[FLAG] = '1';
});

afterEach(async () => {
  delete process.env[FLAG];
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_SECRETS_ADV', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(secretsAdvEnabled()).toBe(false);
    process.env[FLAG] = 'true';
    expect(secretsAdvEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(secretsAdvEnabled()).toBe(true);
  });
});

describe('default scan does not emit Phase-30-only IDs', () => {
  it('vulnerable-app and clean-app stay free of SECRET-BUNDLE-001 without the flag', async () => {
    delete process.env[FLAG];
    const vuln = await scan({ cwd: vulnerableApp, modules: ['secrets'], offline: true });
    const clean = await scan({ cwd: cleanApp, modules: ['secrets'], offline: true });
    for (const f of [...vuln.findings, ...clean.findings]) {
      expect(PHASE30_ONLY_IDS).not.toContain(f.ruleId);
    }
  });

  it('even with the flag, a default scan (no --history/--bundle) does not emit Phase-30-only IDs', async () => {
    const vuln = await scan({ cwd: vulnerableApp, modules: ['secrets'], offline: true });
    const clean = await scan({ cwd: cleanApp, modules: ['secrets'], offline: true });
    for (const f of [...vuln.findings, ...clean.findings]) {
      expect(PHASE30_ONLY_IDS).not.toContain(f.ruleId);
    }
  });
});

describe('scan --history', () => {
  it('finds a secret added and later removed, with first-introduced commit and stillAtHead false', async () => {
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const k = "${AWS_KEY}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'add key');
    const introduced = git(dir, 'rev-parse', 'HEAD');
    await writeFile(join(dir, 'app.js'), 'const k = "rotated";\n');
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'remove key');

    const result = await scan({ cwd: dir, modules: ['secrets'], history: true });
    const aws = result.findings.filter((f) => f.ruleId === 'SECRET-AWS-001');
    expect(aws.length).toBeGreaterThanOrEqual(1);
    expect(aws.some((f) => f.stillAtHead === false)).toBe(true);
    expect(aws.some((f) => f.introducedIn === introduced)).toBe(true);
    expect(JSON.stringify(result.findings)).not.toContain(AWS_KEY);
  });

  it('does nothing useful without the experimental flag', async () => {
    delete process.env[FLAG];
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const k = "${AWS_KEY}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'add key');
    await writeFile(join(dir, 'app.js'), 'const k = "rotated";\n');
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'remove key');

    const result = await scan({ cwd: dir, modules: ['secrets'], history: true });
    expect(result.findings.filter((f) => f.ruleId === 'SECRET-AWS-001')).toEqual([]);
  });

  it('dedupes identical blobs and records the first-introduced commit', async () => {
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const k = "${AWS_KEY}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'add key');
    const introduced = git(dir, 'rev-parse', 'HEAD');
    await writeFile(join(dir, 'other.js'), 'const x = 1;\n');
    git(dir, 'add', 'other.js');
    git(dir, 'commit', '-m', 'unrelated');

    const hist = await scanGitHistory(dir);
    const aws = hist.findings.filter((f) => f.ruleId === 'SECRET-AWS-001' && f.file === 'app.js');
    expect(aws).toHaveLength(1);
    expect(aws[0]?.introducedIn).toBe(introduced);
    expect(aws[0]?.stillAtHead).toBe(true);
  });

  it('respects inline suppressions in the introducing blob', async () => {
    dir = await initRepo();
    await writeFile(
      join(dir, 'app.js'),
      `// fullshield-ignore SECRET-AWS-001: rotated\nconst k = "${AWS_KEY}";\n`,
    );
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'ignored key');
    await writeFile(join(dir, 'app.js'), 'const k = "rotated";\n');
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'remove');

    const result = await scan({ cwd: dir, modules: ['secrets'], history: true });
    expect(result.findings.filter((f) => f.ruleId === 'SECRET-AWS-001')).toEqual([]);
  });

  it('respects baseline for historical findings', async () => {
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const k = "${AWS_KEY}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'add key');
    await writeFile(join(dir, 'app.js'), 'const k = "rotated";\n');
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'remove key');

    const first = await scan({ cwd: dir, modules: ['secrets'], history: true });
    const historical = first.findings.filter((f) => f.ruleId === 'SECRET-AWS-001');
    expect(historical.length).toBeGreaterThan(0);
    await writeBaseline(join(dir, '.fullshield-baseline.json'), historical);

    const second = await scan({ cwd: dir, modules: ['secrets'], history: true });
    expect(second.findings.filter((f) => f.ruleId === 'SECRET-AWS-001')).toEqual([]);
  });

  it('prints scanned N of M commits when the cap is hit, and masks the secret', async () => {
    dir = await initRepo();
    await writeFile(join(dir, 'readme.txt'), 'first\n');
    git(dir, 'add', 'readme.txt');
    git(dir, 'commit', '-m', 'first');
    await writeFile(join(dir, 'other.txt'), 'second\n');
    git(dir, 'add', 'other.txt');
    git(dir, 'commit', '-m', 'second');
    await writeFile(join(dir, 'app.js'), `const k = "${AWS_KEY}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'add key');

    process.env.FULLSHIELD_HISTORY_MAX = '2';
    const result = await scan({ cwd: dir, modules: ['secrets'], history: true });
    expect(result.metadata.history).toBe('scanned 2 of 3 commits');
    const json = renderJsonReport(result);
    const text = renderConsoleReport(result);
    expect(json).toContain('scanned 2 of 3 commits');
    expect(text).toContain('scanned 2 of 3 commits');
    expect(json).toContain('AKIA****');
    expect(text).toContain('AKIA****');
    expect(json).not.toContain(AWS_KEY);
    expect(text).not.toContain(AWS_KEY);
  });

  it('fails clearly outside a git repository', async () => {
    const plain = await mkdtemp(join(tmpdir(), 'fullshield-hist-nogit-'));
    dirs.push(plain);
    await expect(scanGitHistory(plain)).rejects.toThrow(/git repository/i);
  });
});

describe('scan --bundle', () => {
  it('finds a key in the built fixture (dist / .next/static / build)', async () => {
    const result = await scan({ cwd: bundleApp, modules: ['secrets'], bundle: bundleApp });
    const ids = new Set(result.findings.map((f) => f.ruleId));
    expect(ids.has('SECRET-AWS-001') || ids.has('SECRET-STRIPE-001')).toBe(true);
    expect(ids.has('SECRET-BUNDLE-001')).toBe(true);
    const serialized = JSON.stringify(result.findings);
    expect(serialized).not.toContain(AWS_KEY);
    expect(serialized).not.toContain(STRIPE_KEY);
  });

  it('does not flag non-secret NEXT_PUBLIC_/VITE_ values', async () => {
    const hits = await scanBundle(bundleClean);
    expect(hits.findings.filter((f) => f.ruleId === 'SECRET-BUNDLE-001')).toEqual([]);
    expect(hits.findings.filter((f) => f.ruleId.startsWith('SECRET-'))).toEqual([]);
  });

  it('does nothing useful without the experimental flag', async () => {
    delete process.env[FLAG];
    const result = await scan({ cwd: bundleApp, modules: ['secrets'], bundle: bundleApp });
    expect(result.findings.some((f) => f.ruleId === 'SECRET-BUNDLE-001')).toBe(false);
  });

  it('flags NEXT_PUBLIC_ and VITE_ secret-shaped values and not a clean assignment', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'fullshield-bundle-'));
    dirs.push(tmp);
    await mkdir(join(tmp, 'dist'), { recursive: true });
    await writeFile(
      join(tmp, 'dist', 'app.js'),
      `window.env = { NEXT_PUBLIC_TOKEN: "${'AbCdEfGhIjKlMnOpQrStUvWxYz012345'}", VITE_API_URL: "https://ok.example" };\n`,
    );
    const hits = await scanBundle(tmp);
    expect(hits.findings.some((f) => f.ruleId === 'SECRET-BUNDLE-001')).toBe(true);
    expect(hits.findings.some((f) => f.message.includes('VITE_API_URL'))).toBe(false);
  });

  it('does not flag Stripe publishable keys or interpolated values', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'fullshield-bundle-pk-'));
    dirs.push(tmp);
    await mkdir(join(tmp, 'dist'), { recursive: true });
    await writeFile(
      join(tmp, 'dist', 'app.js'),
      `window.env = { NEXT_PUBLIC_PK: "pk_live_${'abcdefghijklmnopqrstuv'}", VITE_MSG: "hello \${x}" };\n`,
    );
    const hits = await scanBundle(tmp);
    expect(hits.findings.filter((f) => f.ruleId === 'SECRET-BUNDLE-001')).toEqual([]);
  });

  it('accepts unquoted NEXT_PUBLIC_ assignments and skips missing dirs', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'fullshield-bundle-uq-'));
    dirs.push(tmp);
    await mkdir(join(tmp, 'dist'), { recursive: true });
    await writeFile(
      join(tmp, 'dist', '.env.production'),
      `NEXT_PUBLIC_TOKEN=${'AbCdEfGhIjKlMnOpQrStUvWxYz012345'}\n`,
    );
    const hits = await scanBundle(tmp);
    expect(hits.findings.some((f) => f.ruleId === 'SECRET-BUNDLE-001')).toBe(true);
    await expect(scanBundle(join(tmp, 'does-not-exist'))).resolves.toEqual({ findings: [], hits: [] });
  });

  it('skips NUL-byte bundle files', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'fullshield-bundle-bin-'));
    dirs.push(tmp);
    await mkdir(join(tmp, 'dist'), { recursive: true });
    await writeFile(join(tmp, 'dist', 'app.js'), Buffer.from([0x41, 0x00, 0x4b, 0x49, 0x41]));
    const hits = await scanBundle(tmp);
    expect(hits.findings).toEqual([]);
  });
});

describe('scan --verify-secrets', () => {
  function hitsFor(ruleId: string, secret: string, file = 'a.js'): SecretHit[] {
    return [
      {
        finding: {
          id: `id-${ruleId}`,
          ruleId,
          module: 'secrets',
          title: ruleId,
          severity: 'high',
          confidence: 'high',
          file,
          line: 1,
          snippet: `${secret.slice(0, 4)}****`,
          message: 'hardcoded',
          remediation: 'rotate',
        },
        secret,
      },
    ];
  }

  function requestUrl(input: Parameters<typeof fetch>[0]): string {
    if (typeof input === 'string') return input;
    if (input instanceof URL) return input.href;
    return input.url;
  }

  function mockFetch(statusFor: (url: string) => { status: number; json?: unknown; text?: string }): typeof fetch {
    const impl: typeof fetch = (input) => {
      const spec = statusFor(requestUrl(input));
      return Promise.resolve({
        ok: spec.status >= 200 && spec.status < 300,
        status: spec.status,
        json: () => Promise.resolve(spec.json ?? {}),
        text: () => Promise.resolve(spec.text ?? ''),
      } as Response);
    };
    return impl;
  }

  it('returns live | revoked | unknown from mocked identity endpoints', async () => {
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
      logs.push(a.map(String).join(' '));
    });
    vi.spyOn(console, 'info').mockImplementation((...a: unknown[]) => {
      logs.push(a.map(String).join(' '));
    });
    vi.spyOn(console, 'warn').mockImplementation((...a: unknown[]) => {
      logs.push(a.map(String).join(' '));
    });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      logs.push(a.map(String).join(' '));
    });

    const live = await verifySecretHits(hitsFor('SECRET-GITHUB-001', GITHUB_TOKEN), {
      fetchImpl: mockFetch((url) => {
        expect(url).toContain('https://api.github.com/user');
        return { status: 200 };
      }),
    });
    expect(live[0]?.finding.verification).toBe('live');

    const revoked = await verifySecretHits(hitsFor('SECRET-STRIPE-001', STRIPE_KEY), {
      fetchImpl: mockFetch((url) => {
        expect(url).toContain('https://api.stripe.com/v1/balance');
        return { status: 401 };
      }),
    });
    expect(revoked[0]?.finding.verification).toBe('revoked');

    const slackLive = await verifySecretHits(hitsFor('SECRET-SLACK-001', SLACK_TOKEN), {
      fetchImpl: mockFetch((url) => {
        expect(url).toContain('https://slack.com/api/auth.test');
        return { status: 200, json: { ok: true } };
      }),
    });
    expect(slackLive[0]?.finding.verification).toBe('live');

    const slackRevoked = await verifySecretHits(hitsFor('SECRET-SLACK-001', SLACK_TOKEN), {
      fetchImpl: mockFetch(() => ({ status: 200, json: { ok: false, error: 'invalid_auth' } })),
    });
    expect(slackRevoked[0]?.finding.verification).toBe('revoked');

    const awsUnknown = await verifySecretHits(hitsFor('SECRET-AWS-001', AWS_KEY), {
      fetchImpl: mockFetch((url) => {
        expect(url).toContain('https://sts.amazonaws.com');
        return { status: 500 };
      }),
    });
    expect(awsUnknown[0]?.finding.verification).toBe('unknown' satisfies VerifyStatus);

    const dumped = `${logs.join('\n')}${JSON.stringify(live.map((h) => h.finding))}${JSON.stringify(revoked.map((h) => h.finding))}${JSON.stringify(slackLive.map((h) => h.finding))}${JSON.stringify(awsUnknown.map((h) => h.finding))}`;
    expect(dumped).not.toContain(GITHUB_TOKEN);
    expect(dumped).not.toContain(STRIPE_KEY);
    expect(dumped).not.toContain(SLACK_TOKEN);
    expect(dumped).not.toContain(AWS_KEY);
  });

  it('live verification is impossible without both --verify-secrets and --i-own-these-credentials', async () => {
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const k = "${GITHUB_TOKEN}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'key');

    const fetchImpl = vi.fn(() => {
      throw new Error('network should not run');
    }) as unknown as typeof fetch;

    const neither = await scan({
      cwd: dir,
      modules: ['secrets'],
      verifyFetch: fetchImpl,
    });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(neither.findings.every((f) => f.verification === undefined)).toBe(true);

    const onlyVerify = await scan({
      cwd: dir,
      modules: ['secrets'],
      verifySecrets: true,
      verifyFetch: fetchImpl,
    });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(onlyVerify.findings.every((f) => f.verification === undefined)).toBe(true);

    const onlyOwn = await scan({
      cwd: dir,
      modules: ['secrets'],
      iOwnTheseCredentials: true,
      verifyFetch: fetchImpl,
    });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(onlyOwn.findings.every((f) => f.verification === undefined)).toBe(true);
  });

  it('does not verify without the experimental flag even with both CLI flags', async () => {
    delete process.env[FLAG];
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const k = "${GITHUB_TOKEN}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'key');

    const fetchImpl = vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
      }),
    ) as unknown as typeof fetch;
    const result = await scan({
      cwd: dir,
      modules: ['secrets'],
      verifySecrets: true,
      iOwnTheseCredentials: true,
      verifyFetch: fetchImpl,
    });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.findings.every((f) => f.verification === undefined)).toBe(true);
  });

  it('calls mocked identity endpoints when both flags and the experimental env are set', async () => {
    dir = await initRepo();
    await writeFile(join(dir, 'app.js'), `const t = "${GITHUB_TOKEN}";\n`);
    git(dir, 'add', 'app.js');
    git(dir, 'commit', '-m', 'key');

    const urls: string[] = [];
    const fetchImpl: typeof fetch = (input) => {
      urls.push(requestUrl(input));
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
      } as Response);
    };

    const result = await scan({
      cwd: dir,
      modules: ['secrets'],
      verifySecrets: true,
      iOwnTheseCredentials: true,
      verifyFetch: fetchImpl,
    });
    expect(urls.some((u) => u.startsWith('https://api.github.com/user'))).toBe(true);
    const gh = result.findings.find((f) => f.ruleId === 'SECRET-GITHUB-001');
    expect(gh?.verification).toBe('live');
    expect(JSON.stringify(result.findings)).not.toContain(GITHUB_TOKEN);
  });

  it('covers identity endpoint branches, empty secrets, and applyVerification', async () => {
    const awsLive = await verifySecretHits(hitsFor('SECRET-AWS-001', AWS_KEY), {
      fetchImpl: mockFetch(() => ({ status: 200 })),
    });
    expect(awsLive[0]?.finding.verification).toBe('live');

    const awsRevoked = await verifySecretHits(hitsFor('SECRET-AWS-001', AWS_KEY), {
      fetchImpl: mockFetch(() => ({ status: 401 })),
    });
    expect(awsRevoked[0]?.finding.verification).toBe('revoked');

    const gh403 = await verifySecretHits(hitsFor('SECRET-GITHUB-001', GITHUB_TOKEN), {
      fetchImpl: mockFetch(() => ({ status: 403 })),
    });
    expect(gh403[0]?.finding.verification).toBe('revoked');

    const slackHttp = await verifySecretHits(hitsFor('SECRET-SLACK-001', SLACK_TOKEN), {
      fetchImpl: mockFetch(() => ({ status: 401 })),
    });
    expect(slackHttp[0]?.finding.verification).toBe('revoked');

    const slackNoOk = await verifySecretHits(hitsFor('SECRET-SLACK-001', SLACK_TOKEN), {
      fetchImpl: mockFetch(() => ({ status: 200, json: { nope: true } })),
    });
    expect(slackNoOk[0]?.finding.verification).toBe('unknown');

    const throws: typeof fetch = () => Promise.reject(new Error('offline'));
    expect(
      (await verifySecretHits(hitsFor('SECRET-GITHUB-001', GITHUB_TOKEN), { fetchImpl: throws }))[0]
        ?.finding.verification,
    ).toBe('unknown');
    expect(
      (await verifySecretHits(hitsFor('SECRET-STRIPE-001', STRIPE_KEY), { fetchImpl: throws }))[0]
        ?.finding.verification,
    ).toBe('unknown');
    expect(
      (await verifySecretHits(hitsFor('SECRET-AWS-001', AWS_KEY), { fetchImpl: throws }))[0]?.finding
        .verification,
    ).toBe('unknown');
    expect(
      (await verifySecretHits(hitsFor('SECRET-SLACK-001', SLACK_TOKEN), { fetchImpl: throws }))[0]
        ?.finding.verification,
    ).toBe('unknown');

    const brokenJson: typeof fetch = () =>
      Promise.resolve({
        ok: false,
        status: 200,
        json: () => Promise.reject(new Error('no json')),
        text: () => Promise.reject(new Error('no text')),
      } as Response);
    expect(
      (await verifySecretHits(hitsFor('SECRET-GITHUB-001', GITHUB_TOKEN), { fetchImpl: brokenJson }))[0]
        ?.finding.verification,
    ).toBe('live');

    const empty = hitsFor('SECRET-GITHUB-001', GITHUB_TOKEN);
    empty[0]!.secret = '';
    expect((await verifySecretHits(empty, { fetchImpl: throws }))[0]?.finding.verification).toBe(
      'unknown',
    );

    const unknownRule = hitsFor('SECRET-ENTROPY-001', 'not-a-known-provider-value');
    expect(
      (await verifySecretHits(unknownRule, { fetchImpl: throws }))[0]?.finding.verification,
    ).toBe('unknown');

    const sast = {
      id: 'sast-1',
      ruleId: 'SAST-SQLI-001',
      module: 'sast' as const,
      title: 'sqli',
      severity: 'high' as const,
      confidence: 'high' as const,
      message: 'x',
      remediation: 'y',
    };
    const ghFinding = hitsFor('SECRET-GITHUB-001', GITHUB_TOKEN)[0]!.finding;
    const mixed = await applyVerification(
      [sast, ghFinding],
      new Map([[ghFinding.id, GITHUB_TOKEN]]),
      { fetchImpl: mockFetch(() => ({ status: 200 })) },
    );
    expect(mixed[0]).toEqual(sast);
    expect(mixed[1]?.verification).toBe('live');
  });
});

describe('scan --history extra edges', () => {
  it('records two paths that share a blob hash and errors on a repo with no commits', async () => {
    dir = await initRepo();
    const body = `const k = "${AWS_KEY}";\n`;
    await writeFile(join(dir, 'a.js'), body);
    await writeFile(join(dir, 'b.js'), body);
    git(dir, 'add', 'a.js', 'b.js');
    git(dir, 'commit', '-m', 'twins');
    const hist = await scanGitHistory(dir);
    const files = hist.findings.filter((f) => f.ruleId === 'SECRET-AWS-001').map((f) => f.file);
    expect(files).toEqual(expect.arrayContaining(['a.js', 'b.js']));

    const empty = await initRepo();
    await expect(scanGitHistory(empty)).rejects.toThrow(/git repository/i);
  });
});
