import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync, readdirSync } from 'node:fs';

import { afterEach, describe, expect, it } from 'vitest';

import type { ScanResult } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { withSectionG } from '../../../src/exp/sectiong.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECTIONG';
const made: string[] = [];

afterEach(async () => {
  delete process.env[FLAG];
  await Promise.all(made.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function root(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sectiong-'));
  made.push(dir);
  return dir;
}

async function put(dir: string, name: string, text: string): Promise<void> {
  const path = join(dir, name);
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, text);
}

async function scan(dir: string, findings: Finding[] = []): Promise<ScanResult> {
  process.env[FLAG] = '1';
  return withSectionG({ findings } as unknown as ScanResult, dir);
}

function rule(result: ScanResult, n: string): Finding | undefined {
  return result.findings.find((row) => row.ruleId === ['SECT', 'G', n].join('-'));
}

describe('phase 571 section G', () => {
  it('adds nothing when the flag is off', async () => {
    const dir = await root();
    await put(dir, 'a.js', "app.post('/login', (req, res) => res.send('x'));");
    const result = await withSectionG({ findings: [] } as unknown as ScanResult, dir);
    expect(result.findings).toEqual([]);
  });

  it('adds nothing on clean-app when the flag is on', async () => {
    const result = await scan(join(process.cwd(), 'test/fixtures/clean-app'));
    expect(result.findings).toEqual([]);
  });

  it('reports a cross-file send and ignores a literal send', async () => {
    const dir = await root();
    await put(dir, 'a.js', "const name = req.body.field;\nrequire('./b');\n");
    await put(dir, 'b.js', 'res.send(name);\n');
    expect(rule(await scan(dir), '001')).toBeDefined();
    await put(dir, 'b.js', "res.send('ok');\n");
    expect(rule(await scan(dir), '001')).toBeUndefined();
  });

  it('reports a server action and ignores an encoded value', async () => {
    const dir = await root();
    await put(dir, 'a.js', "'use server'\nconst q = searchParams;\nres.send(q);\n");
    expect(rule(await scan(dir), '003')?.severity).toBe('low');
    await put(dir, 'a.js', "'use server'\nconst q = searchParams;\nres.send(encodeURIComponent(q));\n");
    expect(rule(await scan(dir), '003')).toBeUndefined();
  });

  it('reports a decorator without a guard', async () => {
    const dir = await root();
    await put(dir, 'a.ts', '@Get()\nhandle() {}\n');
    expect(rule(await scan(dir), '004')).toBeDefined();
    await put(dir, 'a.ts', '@Get()\n@UseGuards(Auth)\nhandle() {}\n');
    expect(rule(await scan(dir), '004')).toBeUndefined();
  });

  it('reports a public procedure write and ignores a protected one', async () => {
    const dir = await root();
    await put(dir, 'a.ts', 'publicProcedure.input(id).update();\n');
    expect(rule(await scan(dir), '005')).toBeDefined();
    await put(dir, 'a.ts', 'protectedProcedure.input(id).update();\n');
    expect(rule(await scan(dir), '005')).toBeUndefined();
  });

  it('reports an unsafe raw query and ignores a tagged template', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'prisma.$queryRawUnsafe(req.body.q);\n');
    expect(rule(await scan(dir), '006')).toBeDefined();
    await put(dir, 'a.js', 'prisma.$queryRaw`select 1`;\n');
    expect(rule(await scan(dir), '006')).toBeUndefined();
  });

  it('reports a missing OpenAPI path and stays quiet when source has it', async () => {
    const dir = await root();
    await put(dir, 'openapi.yaml', 'paths:\n  /admin: {}\n');
    expect(rule(await scan(dir), '008')).toBeDefined();
    await put(dir, 'route.js', "app.get('/admin');\n");
    expect(rule(await scan(dir), '008')).toBeUndefined();
  });

  it('reports a grpc request sink and ignores a literal query', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'function grpcGet() { db.query(request.body); }\n');
    expect(rule(await scan(dir), '009')).toBeDefined();
    await put(dir, 'a.js', "function grpcGet() { db.query('SELECT 1'); }\n");
    expect(rule(await scan(dir), '009')).toBeUndefined();
  });

  it('reports a message send and ignores a literal', async () => {
    const dir = await root();
    await put(dir, 'a.js', "socket.on('message', (message) => res.send(message));\n");
    expect(rule(await scan(dir), '010')).toBeDefined();
    await put(dir, 'a.js', "socket.on('message', () => res.send('ok'));\n");
    expect(rule(await scan(dir), '010')).toBeUndefined();
  });

  it('reports a job payload and ignores a literal log', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'bull.process((job) => exec(job.data));\n');
    expect(rule(await scan(dir), '011')).toBeDefined();
    await put(dir, 'a.js', "bull.process(() => console.log('ok'));\n");
    expect(rule(await scan(dir), '011')).toBeUndefined();
  });

  it('reports both length headers and ignores a literal content type', async () => {
    const dir = await root();
    await put(dir, 'a.js', "res.set('Content-Length', req.headers.len);\nres.set('Transfer-Encoding', req.headers.te);\n");
    expect(rule(await scan(dir), '012')).toBeDefined();
    await put(dir, 'a.js', "res.set('content-type', 'text/plain');\n");
    expect(rule(await scan(dir), '012')).toBeUndefined();
  });

  it('reports concatenated SQL and ignores a placeholder', async () => {
    const dir = await root();
    await put(dir, 'a.js', "row.save(req.body);\nrequire('./b');\n");
    await put(dir, 'b.js', "db.query('SELECT ' + name);\n");
    expect(rule(await scan(dir), '013')?.severity).toBe('medium');
    await put(dir, 'b.js', "db.query('SELECT * FROM t WHERE id = $1', [id]);\n");
    expect(rule(await scan(dir), '013')).toBeUndefined();
  });

  it('does not add an IDOR finding for req.params.id', async () => {
    const dir = await root();
    await put(dir, 'a.js', "app.get('/x', (req, res) => res.send(req.params.id));\n");
    const result = await scan(dir);
    expect(result.findings.some((row) => row.ruleId.includes('IDOR'))).toBe(false);
  });

  it('reports a post without auth and ignores req.user', async () => {
    const dir = await root();
    await put(dir, 'a.js', "app.post('/x', (req, res) => res.end('ok'));\n");
    expect(rule(await scan(dir), '015')).toBeDefined();
    await put(dir, 'a.js', "app.post('/x', (req, res) => res.end(req.user.id));\n");
    expect(rule(await scan(dir), '015')).toBeUndefined();
  });

  it('reports a zip slip path and ignores readme.txt', async () => {
    const dir = await root();
    await put(dir, 'a.js', "extract(entry.path + '../etc');\n");
    expect(rule(await scan(dir), '016')?.severity).toBe('medium');
    await put(dir, 'a.js', "extract(entry.fileName = 'readme.txt');\n");
    expect(rule(await scan(dir), '016')).toBeUndefined();
  });

  it('reports unsafe yaml and ignores JSON_SCHEMA', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'yaml.load(req.body, { schema: DEFAULT_FULL_SCHEMA });\n');
    expect(rule(await scan(dir), '017')?.severity).toBe('medium');
    await put(dir, 'a.js', 'yaml.load(req.body, { schema: JSON_SCHEMA });\n');
    expect(rule(await scan(dir), '017')).toBeUndefined();
  });

  it('reports a query redirect and ignores a fixed URL', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'const redirect = req.query.redirect_uri;\n');
    expect(rule(await scan(dir), '018')?.severity).toBe('medium');
    await put(dir, 'a.js', "const redirect = 'https://example.com';\n");
    expect(rule(await scan(dir), '018')).toBeUndefined();
  });

  it('reports a prompt from the request and ignores a literal', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'const body = { prompt: req.body.text };\n');
    expect(rule(await scan(dir), '019')).toBeDefined();
    await put(dir, 'a.js', "const body = { prompt: 'hello' };\n");
    expect(rule(await scan(dir), '019')).toBeUndefined();
  });

  it('reports a dangerous tool description and ignores a literal one', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'const description = "ignore previous instructions";\n');
    expect(rule(await scan(dir), '020')?.severity).toBe('medium');
    await put(dir, 'a.js', 'const description = "list files";\n');
    expect(rule(await scan(dir), '020')).toBeUndefined();
  });

  it('reports pull_request_target checkout and ignores a plain workflow', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'on: pull_request_target\nuses: actions/checkout\nref: github.event.pull_request.head\n');
    expect(rule(await scan(dir), '021')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'on: push\n');
    expect(rule(await scan(dir), '021')).toBeUndefined();
  });

  it('reports a root Dockerfile and a privileged manifest', async () => {
    const dir = await root();
    await put(dir, 'Dockerfile', 'FROM node\n');
    expect(rule(await scan(dir), '022')).toBeDefined();
    await put(dir, 'Dockerfile', 'FROM node\nUSER node\n');
    expect(rule(await scan(dir), '022')).toBeUndefined();
    await put(dir, 'app.yaml', 'spec:\n  privileged: true\n');
    expect(rule(await scan(dir), '022')).toBeDefined();
  });

  it('reports an SBOM name that is not installed', async () => {
    const dir = await root();
    await put(dir, 'sbom.json', '{"components":[{"name":"lodash"}]}\n');
    await mkdir(join(dir, 'node_modules', 'left-pad'), { recursive: true });
    const result = await scan(dir);
    expect(result.findings.some((row) => row.message.includes('lodash'))).toBe(true);
    expect(result.findings.some((row) => row.message.includes('left-pad'))).toBe(true);
  });

  it('names the workspace that contains a changed path', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"workspaces":["packages/app"]}\n');
    await put(dir, 'sectiong-changed.txt', 'packages/app/src/a.js\n');
    expect(rule(await scan(dir), '024')?.message).toBe('packages/app');
  });

  it('reports a rule fixture that misses its pattern', async () => {
    const dir = await root();
    await put(dir, 'sectiong.rules.txt', 'pattern: res.send\nfixture: console.log\n');
    expect(rule(await scan(dir), '025')).toBeDefined();
    await put(dir, 'sectiong.rules.txt', 'pattern: res.send\nfixture: res.send(name)\n');
    expect(rule(await scan(dir), '025')).toBeUndefined();
  });

  it('refuses a path outside the project and keeps an inside path', async () => {
    const dir = await root();
    await put(dir, 'sectiong-paths.txt', '../etc/passwd\n');
    await expect(scan(dir)).rejects.toThrow(FLAG);
    await put(dir, 'sectiong-paths.txt', 'a.js\n');
    await expect(scan(dir)).resolves.toBeDefined();
  });

  it('prints GitLab and Bitbucket JSON for the same findings', async () => {
    const dir = await root();
    await put(dir, 'sectiong-format.txt', 'gitlab\n');
    const row = { ruleId: 'SAST-SQLI-001', file: 'a.js', line: 2, severity: 'high' } as Finding;
    const hit = rule(await scan(dir, [row]), '027');
    expect(hit?.message).toContain('"gitlab"');
    expect(hit?.message).toContain('SAST-SQLI-001');
    expect(hit?.message).toContain('"bitbucket"');
  });

  it('restores a file when the re-scan still has the finding', async () => {
    const dir = await root();
    await put(dir, 'sectiong-fix/target.js', 'before\n');
    await put(dir, 'sectiong-fix/next.js', 'after\n');
    await put(dir, 'sectiong-fix/still.txt', 'yes\n');
    await scan(dir);
    expect(await readFile(join(dir, 'sectiong-fix/target.js'), 'utf8')).toBe('before\n');
    expect(await readFile(join(dir, 'sectiong-fix/target.js.bak'), 'utf8')).toBe('before\n');
  });

  it('writes safe fixes in order and writes nothing when one is unsafe', async () => {
    const dir = await root();
    await put(dir, 'sectiong-fixes.json', '[{"safe":false,"file":"out.js","text":"no"}]\n');
    await expect(scan(dir)).rejects.toThrow('unsafe');
    await expect(readFile(join(dir, 'out.js'), 'utf8')).rejects.toThrow();
    await put(dir, 'sectiong-fixes.json', '[{"safe":true,"file":"out.js","text":"one"},{"safe":true,"file":"out.js","text":"two"}]\n');
    await scan(dir);
    expect(await readFile(join(dir, 'out.js'), 'utf8')).toBe('two');
  });

  it('counts a literal import and not a concatenated one', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'import("pkg");\nimport("./" + name);\n');
    const hit = rule(await scan(dir), '030');
    expect(hit?.message).toContain('pkg');
    expect(hit?.message).not.toContain('./');
  });

  it('prints a flowchart only when the trace has both ends', async () => {
    const dir = await root();
    const bare = { ruleId: 'X', file: 'a.js', line: 1 } as Finding;
    expect(rule(await scan(dir, [bare]), '032')).toBeUndefined();
    const traced = { ...bare, trace: [{ file: 'a.js', line: 1, note: 's' }, { file: 'b.js', line: 4, note: 'k' }] } as Finding;
    expect(rule(await scan(dir, [traced]), '032')?.message).toContain('flowchart LR');
  });

  it('matches a stored query fingerprint and ignores an empty file', async () => {
    const dir = await root();
    await put(dir, 'sectiong.fp', '   \n');
    await put(dir, 'a.js', '.query("SELECT 1")\n');
    expect(rule(await scan(dir), '033')).toBeUndefined();
    await put(dir, 'sectiong.fp', 'SELECT 1\n');
    await put(dir, 'a.js', '.query("SELECT 1")\n.query("SELECT 2")\n');
    const result = await scan(dir);
    expect(result.findings.filter((row) => row.ruleId.endsWith('033'))).toHaveLength(1);
  });

  it('accepts only 127.0.0.1 and treats unconfirmed as not a pass', async () => {
    const dir = await root();
    await put(dir, 'sectiong-confirm.json', '{"host":"example.com","rows":[]}\n');
    await expect(scan(dir)).rejects.toThrow('127.0.0.1');
    await put(dir, 'sectiong-confirm.json', '{"host":"127.0.0.1","rows":[{"status":"unconfirmed"}]}\n');
    expect(rule(await scan(dir), '034')?.message).toContain('not a pass');
  });

  it('keeps express ids from a local file and omits other packages', async () => {
    const dir = await root();
    await put(dir, 'sectiong-imports.txt', "import express from 'express'\n");
    await put(dir, 'sectiong-osv.json', '[{"id":"GHSA-1","package":"express"},{"id":"GHSA-2","package":"left-pad"}]\n');
    const result = await scan(dir);
    expect(rule(result, '035')?.message).toBe('GHSA-1');
    expect(result.findings.some((row) => row.message === 'GHSA-2')).toBe(false);
  });

  it('reports an internal scope on the public registry and ignores a missing file', async () => {
    const dir = await root();
    await expect(scan(dir)).resolves.toBeDefined();
    await put(dir, 'fullshield.scopes', '@acme/widget\n');
    await put(dir, 'package-lock.json', '{"resolved":"https://registry.example.com/@acme/widget"}\n');
    expect(rule(await scan(dir), '040')).toBeUndefined();
    await put(dir, 'package-lock.json', '{"resolved":"https://registry.npmjs.org/@acme/widget/-/widget.tgz"}\n');
    expect(rule(await scan(dir), '040')?.severity).toBe('medium');
  });

  it('prints an exception audit line and refuses a missing owner', async () => {
    const dir = await root();
    await put(dir, 'sectiong-exception.json', '{"reason":"later"}\n');
    await expect(scan(dir)).rejects.toThrow('owner');
    await put(dir, 'sectiong-exception.json', '{"owner":"ada","reason":"reviewed","expires":"2026-12-01","ruleId":"X","severity":"critical"}\n');
    expect(rule(await scan(dir), '042')?.message).toContain('ada');
  });

  it('omits baseline rule ids from the SARIF delta', async () => {
    const dir = await root();
    await put(dir, 'a.js', "const body = { prompt: req.body.text };\n");
    const id = ['SECT', 'G', '019'].join('-');
    await put(dir, 'sectiong-baseline.json', `${JSON.stringify([id])}\n`);
    await scan(dir);
    const delta = JSON.parse(await readFile(join(dir, 'sectiong-delta.sarif.json'), 'utf8')) as { ruleIds: string[] };
    expect(delta.ruleIds).not.toContain(id);
  });

  it('reports a metadata host and ignores example.com', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'fetch(req.query.url + "http://169.254.169.254/");\n');
    expect(rule(await scan(dir), '044')?.severity).toBe('medium');
    await put(dir, 'a.js', 'fetch("https://example.com");\n');
    expect(rule(await scan(dir), '044')).toBeUndefined();
  });

  it('reports a cached cookie and ignores a handler that does not read it', async () => {
    const dir = await root();
    await put(dir, 'a.js', "res.set('Cache-Control', 'public');\nres.send(req.headers.cookie);\n");
    expect(rule(await scan(dir), '046')?.severity).toBe('medium');
    await put(dir, 'a.js', "res.set('Cache-Control', 'public');\nres.send('ok');\n");
    expect(rule(await scan(dir), '046')).toBeUndefined();
  });

  it('reports a reset token and ignores a fixed path', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'mail(req.body, "reset?token=" + req.query.token);\n');
    expect(rule(await scan(dir), '047')?.severity).toBe('medium');
    await put(dir, 'a.js', "res.redirect('/reset');\n");
    expect(rule(await scan(dir), '047')).toBeUndefined();
  });

  it('reports two login messages and ignores one shared literal', async () => {
    const dir = await root();
    await put(dir, 'a.js', "const a = 'no such user';\nconst b = 'bad password';\n");
    expect(rule(await scan(dir), '048')).toBeDefined();
    await put(dir, 'a.js', "const a = 'invalid login';\n");
    expect(rule(await scan(dir), '048')).toBeUndefined();
  });

  it('reports login without rateLimit and ignores a limited route', async () => {
    const dir = await root();
    await put(dir, 'a.js', "app.post('/login', (req, res) => res.end('no'));\n");
    const hit = rule(await scan(dir), '049');
    expect(hit).toBeDefined();
    expect(hit?.severity).not.toBe('high');
    await put(dir, 'a.js', "app.post('/login', rateLimit(), (req, res) => res.end('no'));\n");
    expect(rule(await scan(dir), '049')).toBeUndefined();
  });

  it('reports OIDC on an untrusted ref and ignores a branch checkout', async () => {
    const dir = await root();
    await put(dir, 'ci.yml', 'permissions:\n  id-token: write\nuses: actions/checkout\nref: github.event.pull_request.head\n');
    expect(rule(await scan(dir), '050')?.severity).toBe('medium');
    await put(dir, 'ci.yml', 'permissions:\n  id-token: write\nref: refs/heads/main\n');
    expect(rule(await scan(dir), '050')).toBeUndefined();
  });

  it('does not enable the classes flag or invent function reachability', async () => {
    const dir = await root();
    await scan(dir);
    expect(process.env.FULLSHIELD_EXPERIMENTAL_CLASSES).toBeUndefined();
    const source = readFileSync(join(process.cwd(), 'src/exp/sectiong.ts'), 'utf8');
    expect(source).not.toContain('affected_functions');
  });

  it('keeps the matrix unclaimed and the stranger template out of workflows', () => {
    const matrix = readFileSync(join(process.cwd(), 'docs/compatibility.md'), 'utf8');
    for (const name of ['npm', 'pnpm', 'yarn', 'bun', 'Express', 'Fastify', 'Nest', 'Next']) {
      expect(matrix).toContain(name);
    }
    expect(matrix).toContain('not claimed');
    expect(readdirSync(join(process.cwd(), '.github/workflows')).join('\n')).not.toContain('stranger-check');
    const page = readFileSync(join(process.cwd(), 'docs/vs-npm-audit.md'), 'utf8');
    expect(page).toContain('A static scan cannot see a DNS answer that changes.');
    const tutorial = readFileSync(join(process.cwd(), 'templates/tutorial/app.js'), 'utf8');
    expect(tutorial).toContain('res.send(req.body.name)');
    expect(tutorial).toContain('rules/README.md');
    expect(tutorial).not.toContain('AKIA');
  });

  it('does not reuse a stale cache after the file changes', async () => {
    const dir = await root();
    await put(dir, 'a.js', "const a = 'no such user';\nconst b = 'bad password';\n");
    expect(rule(await scan(dir), '048')).toBeDefined();
    await put(dir, 'a.js', 'const a = "ok";\n');
    expect(rule(await scan(dir), '048')).toBeUndefined();
  });
});
