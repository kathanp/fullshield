import { readFileSync, readdirSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { ScanResult } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { withSectionH } from '../../../src/exp/sectionh.js';
import { withSectionH2 } from '../../../src/exp/sectionh2.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECTIONG';
const made: string[] = [];

afterEach(async () => {
  delete process.env[FLAG];
  await Promise.all(made.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function root(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sectionh2-'));
  made.push(dir);
  return dir;
}

async function put(dir: string, name: string, text: string): Promise<void> {
  const path = join(dir, name);
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, text);
}

function input(ruleId: string, file: string, message = 'note'): Finding {
  return {
    id: 'input',
    ruleId,
    module: 'sast',
    title: 'input',
    severity: 'high',
    confidence: 'low',
    file,
    line: 4,
    message,
    remediation: 'review',
    source: 'rule',
  };
}

async function scan(dir: string, findings: Finding[] = []): Promise<ScanResult> {
  process.env[FLAG] = '1';
  return withSectionH2({ findings } as unknown as ScanResult, dir);
}

function rule(result: ScanResult, n: string): Finding | undefined {
  return result.findings.find((row) => row.ruleId === ['SECT', 'H', n].join('-'));
}

describe('phase 573 section H auth, CI, and output', () => {
  it('adds nothing when the flag is off', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'res.redirect(authorizeUrl);\n');
    await put(dir, 'sectionh-report.txt', '1\n');
    const result = await withSectionH2({ findings: [] } as unknown as ScanResult, dir);
    expect(result.findings).toEqual([]);
    await expect(stat(join(dir, 'sectionh-report.json'))).rejects.toThrow();
  });

  it('adds nothing on clean-app when the flag is on', async () => {
    const clean = join(process.cwd(), 'test/fixtures/clean-app');
    process.env[FLAG] = '1';
    const first = await withSectionH({ findings: [] } as unknown as ScanResult, clean);
    const result = await withSectionH2(first, clean);
    expect(result.findings).toEqual([]);
  });

  it('reports an oauth redirect without state and ignores state or a verifier', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'res.redirect(authorizeUrl);\n');
    expect(rule(await scan(dir), '028')?.severity).toBe('medium');
    await put(dir, 'a.js', 'res.redirect(authorizeUrl + state);\n');
    expect(rule(await scan(dir), '028')).toBeUndefined();
    await put(dir, 'b.js', 'fetch(tokenUrl, { code });\n');
    expect(rule(await scan(dir), '028')).toBeDefined();
    await put(dir, 'b.js', 'fetch(tokenUrl, { code, verifier });\n');
    expect(rule(await scan(dir), '028')).toBeUndefined();
  });

  it('reports an open redirect and ignores a fixed path or an array', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'res.redirect(req.query.next);\n');
    expect(rule(await scan(dir), '029')?.severity).toBe('medium');
    await put(dir, 'a.js', 'res.redirect("/home");\n');
    expect(rule(await scan(dir), '029')).toBeUndefined();
    await put(dir, 'a.js', 'const ok = ["/home"];\nres.redirect(req.query.return);\n');
    expect(rule(await scan(dir), '029')).toBeUndefined();
  });

  it('reports a literal secret and ignores process.env', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'const x = { secret: "abc" };\n');
    expect(rule(await scan(dir), '030')?.severity).toBe('medium');
    await put(dir, 'a.js', "jwt.sign(payload, 'literal');\n");
    expect(rule(await scan(dir), '030')).toBeDefined();
    await put(dir, 'a.js', 'jwt.sign(payload, process.env.JWT_SECRET);\n');
    expect(rule(await scan(dir), '030')).toBeUndefined();
  });

  it('reports a none cookie without secure and ignores secure or a test path', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'res.setHeader("Set-Cookie", "a=b; SameSite=None");\n');
    expect(rule(await scan(dir), '031')?.severity).toBe('medium');
    await put(dir, 'a.js', "res.cookie('a', 'b', { sameSite: 'none' });\n");
    expect(rule(await scan(dir), '031')).toBeDefined();
    await put(dir, 'a.js', "res.cookie('a', 'b', { sameSite: 'none', secure: true });\n");
    expect(rule(await scan(dir), '031')).toBeUndefined();
    await put(dir, 'test/a.js', "res.cookie('a', 'b', { sameSite: 'none' });\n");
    expect(rule(await scan(dir), '031')).toBeUndefined();
  });

  it('reports a password hash of md5 or sha1 and ignores bcrypt', async () => {
    const dir = await root();
    await put(dir, 'a.js', "createHash('md5');\nconst password = 1;\n");
    expect(rule(await scan(dir), '032')?.severity).toBe('medium');
    await put(dir, 'a.js', "createHash('sha1');\npassword;\n");
    expect(rule(await scan(dir), '032')).toBeDefined();
    await put(dir, 'a.js', 'createHash("md5");\npassword;\n');
    expect(rule(await scan(dir), '032')).toBeDefined();
    await put(dir, 'a.js', 'createHash("sha1");\npassword;\n');
    expect(rule(await scan(dir), '032')).toBeDefined();
    await put(dir, 'a.js', 'bcrypt.hash(password);\n');
    expect(rule(await scan(dir), '032')).toBeUndefined();
  });

  it('reports an account update and ignores a current password or a session', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'db.update({ email });\n');
    expect(rule(await scan(dir), '033')?.severity).toBe('low');
    await put(dir, 'a.js', 'db.update({ email, currentPassword });\n');
    expect(rule(await scan(dir), '033')).toBeUndefined();
    await put(dir, 'a.js', 'db.update({ password: req.session.user });\n');
    expect(rule(await scan(dir), '033')).toBeUndefined();
  });

  it('reports a presign without expiry and ignores expiresIn or Expires', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'getSignedUrl(cmd);\n');
    expect(rule(await scan(dir), '034')?.severity).toBe('low');
    await put(dir, 'a.js', 'presign(cmd, { expiresIn: 60 });\n');
    expect(rule(await scan(dir), '034')).toBeUndefined();
    await put(dir, 'a.js', 'presign(cmd, { Expires: 60 });\n');
    expect(rule(await scan(dir), '034')).toBeUndefined();
  });

  it('reports public-read in application source and ignores terraform text', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'acl: "public-read"\n');
    expect(rule(await scan(dir), '035')?.severity).toBe('medium');
    await put(dir, 'a.js', 'acl: "public-read-write"\n');
    expect(rule(await scan(dir), '035')).toBeDefined();
    await put(dir, 'a.js', 'acl: "private"\n');
    await put(dir, 'ci.yml', 'acl: public-read\n');
    expect(rule(await scan(dir), '035')).toBeUndefined();
  });

  it('reports a workflow run that interpolates an event and ignores a plain run', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'run: echo ${{ github.event.head_commit }}\n');
    expect(rule(await scan(dir), '036')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'run: echo hi\n');
    expect(rule(await scan(dir), '036')).toBeUndefined();
  });

  it('reports an unpinned uses value and ignores checkout, setup-node, and a 40-hex pin', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'uses: other/action@v1\n');
    expect(rule(await scan(dir), '037')?.severity).toBe('low');
    await put(dir, 'ci.yml', 'uses: actions/checkout@v4\n');
    expect(rule(await scan(dir), '037')).toBeUndefined();
    await put(dir, 'ci.yml', 'uses: actions/setup-node@v4\n');
    expect(rule(await scan(dir), '037')).toBeUndefined();
    await put(dir, 'ci.yml', `uses: other/action@${'a'.repeat(40)}\n`);
    expect(rule(await scan(dir), '037')).toBeUndefined();
  });

  it('reports a third-party action with a secret in the same job', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'jobs:\n  build:\n    steps:\n      - uses: other/action@v1\n        env:\n          TOKEN: ${{ secrets.TOKEN }}\n');
    expect(rule(await scan(dir), '038')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'jobs:\n  one:\n    steps:\n      - uses: other/action@v1\n  two:\n    steps:\n      - run: echo ${{ secrets.TOKEN }}\n');
    expect(rule(await scan(dir), '038')).toBeUndefined();
    await put(dir, 'ci.yml', 'jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        env:\n          TOKEN: ${{ secrets.TOKEN }}\n');
    expect(rule(await scan(dir), '038')).toBeUndefined();
  });

  it('reports persisted credentials on pull_request and ignores false', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'on:\n  pull_request:\n    persist-credentials: true\n');
    expect(rule(await scan(dir), '039')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'on:\n  pull_request:\n    persist-credentials: false\n');
    expect(rule(await scan(dir), '039')).toBeUndefined();
  });

  it('reports a pull_request write token and ignores a push-only workflow', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'on:\n  pull_request:\npermissions:\n  contents: write\n');
    expect(rule(await scan(dir), '040')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'on:\n  pull_request:\npermissions:\n  id-token: write\n');
    expect(rule(await scan(dir), '040')).toBeDefined();
    await put(dir, 'ci.yml', 'on:\n  push:\npermissions:\n  contents: write\n');
    expect(rule(await scan(dir), '040')).toBeUndefined();
  });

  it('reports an ignore file without .env and ignores a missing file', async () => {
    const dir = await root();
    expect(rule(await scan(dir), '041')).toBeUndefined();
    await put(dir, '.gitignore', 'node_modules\n');
    expect(rule(await scan(dir), '041')?.severity).toBe('low');
    await put(dir, '.gitignore', '.env\n');
    expect(rule(await scan(dir), '041')).toBeUndefined();
    await rm(join(dir, '.gitignore'));
    await put(dir, '.dockerignore', 'node_modules\n');
    expect(rule(await scan(dir), '041')).toBeDefined();
    await put(dir, '.dockerignore', '.env\n');
    expect(rule(await scan(dir), '041')).toBeUndefined();
  });

  it('reports a Dockerfile secret copy and ignores a package copy', async () => {
    const dir = await root();
    await put(dir, 'Dockerfile', 'COPY .env /app/.env\n');
    expect(rule(await scan(dir), '042')?.severity).toBe('medium');
    await put(dir, 'Dockerfile', 'ARG id_rsa\n');
    expect(rule(await scan(dir), '042')).toBeDefined();
    await put(dir, 'Dockerfile', 'ENV NPM_CONFIG=/root/.npmrc\n');
    expect(rule(await scan(dir), '042')).toBeDefined();
    await put(dir, 'Dockerfile', 'COPY package.json .\n');
    expect(rule(await scan(dir), '042')).toBeUndefined();
  });

  it('reports a quoted compose password and ignores an interpolation', async () => {
    const dir = await root();
    await put(dir, 'docker-compose.yml', 'ports:\n  - "5432:5432"\n  PASSWORD: "secret"\n');
    expect(rule(await scan(dir), '043')?.severity).toBe('medium');
    await put(dir, 'docker-compose.yml', 'ports:\n  - "5432:5432"\n  PASSWORD: ${DB_PASSWORD}\n');
    expect(rule(await scan(dir), '043')).toBeUndefined();
  });

  it('reports npm publish with a node token and ignores an id-token workflow', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'run: npm publish\nenv:\n  NODE_AUTH_TOKEN: abc\n');
    expect(rule(await scan(dir), '044')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'permissions:\n  id-token: write\nrun: npm publish\nenv:\n  NODE_AUTH_TOKEN: abc\n');
    expect(rule(await scan(dir), '044')).toBeUndefined();
  });

  it('emits reviewdog JSON for the input findings', async () => {
    const dir = await root();
    await put(dir, 'sectionh-format.txt', '1\n');
    const result = await scan(dir, [input('SAST-X-001', 'a.js')]);
    const body = JSON.parse(rule(result, '045')?.message ?? '') as {
      reviewdog: Array<{ ruleId: string; file: string; line: number; severity: string }>;
    };
    expect(body.reviewdog[0]).toEqual({ ruleId: 'SAST-X-001', file: 'a.js', line: 4, severity: 'high' });
  });

  it('ships a scan schema with schemaVersion and no required field', () => {
    const schema = JSON.parse(readFileSync('docs/scan-result.schema.json', 'utf8')) as {
      schemaVersion?: number;
      required?: unknown;
    };
    expect(schema.schemaVersion).toBe(1);
    expect(schema.required).toBeUndefined();
    expect(JSON.stringify(schema)).toContain('"schemaVersion"');
  });

  it('names a missing or old cache and ignores a fresh cache', async () => {
    const dir = await root();
    await put(dir, 'sectionh-doctor.txt', '1\n');
    expect(rule(await scan(dir), '047')?.message).toContain('missing');
    await put(dir, 'sectionh-osv-cache.json', '{}\n');
    const old = new Date('2020-01-01T00:00:00Z');
    await utimes(join(dir, 'sectionh-osv-cache.json'), old, old);
    const aged = rule(await scan(dir), '047');
    expect(aged?.message).toContain('days');
    expect(Number((aged?.message ?? '').match(/(\d+)/)?.[1] ?? '0')).toBeGreaterThan(1);
    await utimes(join(dir, 'sectionh-osv-cache.json'), new Date(), new Date());
    await put(dir, 'sectionh-doctor.txt', '4000\n');
    expect(rule(await scan(dir), '047')).toBeUndefined();
    await put(dir, 'sectionh-doctor.txt', 'soon\n');
    expect(rule(await scan(dir), '047')).toBeUndefined();
  });

  it('reports relative input paths and omits an absolute prefix', async () => {
    const dir = await root();
    await put(dir, 'sectionh-relative.txt', '1\n');
    const abs = join(dir, 'src', 'a.js');
    const absolute = await scan(dir, [input('SAST-X-001', abs)]);
    expect(rule(absolute, '048')?.message).toContain('src/a.js');
    expect(rule(absolute, '048')?.message).not.toContain(dir);
    const relative = await scan(dir, [input('SAST-X-001', 'lib/b.js')]);
    expect(rule(relative, '048')?.message).toContain('lib/b.js');
  });

  it('masks a listed line and leaves a report unchanged when the file is absent', async () => {
    const dir = await root();
    const plain = await scan(dir, [input('SAST-X-001', 'a.js', 'token MASKEDTOKEN here')]);
    expect(plain.findings[0]?.message).toBe('token MASKEDTOKEN here');
    await put(dir, 'sectionh-mask.txt', 'MASKEDTOKEN\n');
    const masked = await scan(dir, [input('SAST-X-001', 'a.js', 'token MASKEDTOKEN here')]);
    expect(masked.findings.find((row) => row.ruleId === 'SAST-X-001')?.message).toBe('token [masked] here');
    expect(JSON.stringify(masked)).not.toContain('MASKEDTOKEN');
  });

  it('writes the report mode 0600 with the input rule ids', async () => {
    const dir = await root();
    await put(dir, 'sectionh-report.txt', '1\n');
    await scan(dir, [input('SAST-X-001', 'a.js')]);
    const body = JSON.parse(await readFile(join(dir, 'sectionh-report.json'), 'utf8')) as { ruleIds: string[] };
    expect(body.ruleIds).toEqual(['SAST-X-001']);
    if (process.platform !== 'win32') {
      expect((await stat(join(dir, 'sectionh-report.json'))).mode & 0o777).toBe(0o600);
    }
  });

  it('skips source files when the lockfile-only marker exists and still reads lockfiles', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'app.listen(3000);\nres.redirect(authorizeUrl);\n');
    await put(dir, 'package-lock.json', '{"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}\n');
    await put(dir, 'yarn.lock', 'left-pad@^1.0.0:\n  version "2.0.0"\n');
    await put(dir, 'ci.yml', 'run: echo ${{ github.event.head_commit }}\n');
    await put(dir, 'sectionh-lockonly.txt', '1\n');
    process.env[FLAG] = '1';
    const locked = await withSectionH({ findings: [] } as unknown as ScanResult, dir);
    expect(rule(locked, '024')).toBeUndefined();
    expect(rule(locked, '005')).toBeDefined();
    expect(rule(await scan(dir), '028')).toBeUndefined();
    expect(rule(await scan(dir), '036')).toBeDefined();
    await rm(join(dir, 'sectionh-lockonly.txt'));
    const open = await withSectionH({ findings: [] } as unknown as ScanResult, dir);
    expect(rule(open, '024')).toBeDefined();
  });

  it('lists policy rule ids that are in the input', async () => {
    const dir = await root();
    await put(dir, 'sectionh-policy.json', JSON.stringify({ failOn: 'high', ruleIds: ['SAST-A-001', 'SAST-B-001'] }));
    const result = await scan(dir, [input('SAST-A-001', 'a.js'), input('SAST-C-001', 'b.js')]);
    const message = rule(result, '053')?.message ?? '';
    expect(message).toContain('SAST-A-001');
    expect(message).not.toContain('SAST-C-001');
    await put(dir, 'sectionh-policy.json', '{');
    expect(rule(await scan(dir), '053')).toBeUndefined();
  });

  it('reports a local epss score with unspecified reachability', async () => {
    const dir = await root();
    await put(dir, 'sectionh-epss.json', JSON.stringify({ 'SAST-X-001': 0.2 }));
    const result = await scan(dir, [input('SAST-X-001', 'a.js')]);
    expect(rule(result, '054')?.message).toContain('SAST-X-001 0.2 high unspecified');
  });

  it('prefers an override bump and otherwise a patch bump', async () => {
    const dir = await root();
    await put(dir, 'sectionh-bumps.json', JSON.stringify([
      { name: 'left', from: '1.2.3', to: '1.2.4', override: false },
      { name: 'right', from: '1.0.0', to: '2.0.0', override: true },
    ]));
    expect(rule(await scan(dir), '055')?.message).toContain('right override');
    await put(dir, 'sectionh-bumps.json', JSON.stringify([{ name: 'left', from: '1.2.3', to: '1.2.4' }]));
    expect(rule(await scan(dir), '055')?.message).toContain('left patch');
    await put(dir, 'sectionh-bumps.json', JSON.stringify([{ name: 'left', from: '1.2.3', to: '2.0.0' }]));
    expect(rule(await scan(dir), '055')).toBeUndefined();
  });

  it('names a changed delta field and ignores an unchanged field', async () => {
    const dir = await root();
    await put(dir, 'sectionh-delta.json', JSON.stringify({
      from: { script: 'a', license: 'MIT' },
      to: { script: 'b', license: 'MIT' },
    }));
    expect(rule(await scan(dir), '056')?.message).toContain('script');
    await put(dir, 'sectionh-delta.json', JSON.stringify({ from: { script: 'a' }, to: { script: 'a' } }));
    expect(rule(await scan(dir), '056')).toBeUndefined();
  });

  it('throws before a scan write when the offline marker has no cache', async () => {
    const dir = await root();
    await put(dir, 'sectionh-offline.txt', '1\n');
    await put(dir, 'sectionh-report.txt', '1\n');
    await expect(scan(dir)).rejects.toThrow(/FULLSHIELD_EXPERIMENTAL_SECTIONG/);
    await expect(stat(join(dir, 'sectionh-report.json'))).rejects.toThrow();
    await put(dir, 'sectionh-osv-cache.json', '{}\n');
    await expect(scan(dir)).resolves.toBeDefined();
  });

  it('says this repo is scanned with the default rules and adds no workflow', () => {
    const text = readFileSync('templates/self-scan.md', 'utf8');
    expect(text).toContain('default rules');
    const names = readdirSync('.github/workflows');
    expect(names.some((name) => name.includes('self-scan'))).toBe(false);
    for (const name of names) {
      expect(readFileSync(join('.github/workflows', name), 'utf8')).not.toContain('self-scan');
    }
  });

  it('adds a map name for a dist finding and adds nothing without a map', async () => {
    const dir = await root();
    await put(dir, 'dist/app.js.map', '{}\n');
    const mapped = await scan(dir, [input('SAST-X-001', 'dist/app.js', 'built')]);
    expect(mapped.findings.find((row) => row.ruleId === 'SAST-X-001')?.message).toContain('app.js.map');
    const plainDir = await root();
    const plain = await scan(plainDir, [input('SAST-X-001', 'dist/app.js', 'built')]);
    expect(plain.findings.find((row) => row.ruleId === 'SAST-X-001')?.message).toBe('built');
    const other = await scan(dir, [input('SAST-X-001', 'src/a.js', 'built')]);
    expect(other.findings.find((row) => row.ruleId === 'SAST-X-001')?.message).toBe('built');
  });
});
