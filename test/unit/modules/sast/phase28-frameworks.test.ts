import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { parseSource, runSastOnText } from '../../../../src/modules/sast/engine.js';
import { inventoryRoutes } from '../../../../src/modules/sast/frameworks.js';
import { shieldGuard as honoGuard } from '../../../../src/runtime/hono.js';
import { shieldGuard as koaGuard } from '../../../../src/runtime/koa.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_FRAMEWORKS';
const root = join(process.cwd(), 'test', 'fixtures', 'frameworks');

async function has(code: string, ruleId: string, filename = 'fixture.ts'): Promise<boolean> {
  return (await runSastOnText(filename, code)).some((f) => f.ruleId === ruleId);
}

async function scanApp(name: string) {
  return scan({ cwd: join(root, name), modules: ['sast'] });
}

function routeKey(r: { method: string; path: string }): string {
  return `${r.method.toUpperCase()} ${r.path}`;
}

async function listed(rel: string): Promise<string[]> {
  const file = join(root, rel);
  const source = await readFile(file, 'utf8');
  const ast = await parseSource(source);
  return inventoryRoutes(rel, ast).map(routeKey);
}

describe('Phase 28 — framework taint (experimental)', () => {
  beforeEach(() => {
    process.env[FLAG] = '1';
  });
  afterEach(() => {
    delete process.env[FLAG];
  });

  it('does not treat Next request.json() as taint when the flag is off', async () => {
    delete process.env[FLAG];
    await expect(
      has(
        `export async function GET(request: Request) { User.find(await request.json()); }`,
        'SAST-NOSQLI-001',
      ),
    ).resolves.toBe(false);
  });

  it('flags Next App Router request.json() and searchParams as taint', async () => {
    await expect(
      has(
        `export async function GET(request: Request) { User.find(await request.json()); }`,
        'SAST-NOSQLI-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(
        `export async function GET(request: Request) { db.query('SELECT * FROM t WHERE q = ' + request.nextUrl.searchParams.get('q')); }`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not flag Next request.json() after String() coercion into a parameterized query', async () => {
    await expect(
      has(
        `export async function GET(request: Request) {\n  const session = await auth();\n  const q = String((await request.json()).q);\n  db.query('SELECT * FROM t WHERE q = $1', [q]);\n}`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });

  it('flags Next Server Action formData.get as taint', async () => {
    await expect(
      has(
        `export async function createItem(formData: FormData) { db.query('INSERT ' + formData.get('name')); }`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('flags Nest @Body/@Query parameters as taint', async () => {
    await expect(
      has(
        `class C {\n  @Post()\n  create(@Body() body: any) { User.find(body); }\n}`,
        'SAST-NOSQLI-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(
        `class C {\n  @Get()\n  list(@Query() q: any) { db.query('SELECT ' + q.name); }\n}`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not flag Nest @Query after String() into a parameterized query', async () => {
    await expect(
      has(
        `class C {\n  @UseGuards(AuthGuard)\n  @Get()\n  list(@Query('q') q: string) { db.query('SELECT * FROM t WHERE q = $1', [String(q)]); }\n}`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });

  it('flags Hono c.req.query/json/param as taint', async () => {
    await expect(
      has(`app.get('/x', async (c) => { User.find({ q: c.req.query('q') }); });`, 'SAST-NOSQLI-001'),
    ).resolves.toBe(true);
    await expect(
      has(`app.post('/x', async (c) => { User.find(await c.req.json()); });`, 'SAST-NOSQLI-001'),
    ).resolves.toBe(true);
    await expect(
      has(`app.get('/x/:id', async (c) => { db.query('SELECT ' + c.req.param('id')); });`, 'SAST-SQLI-001'),
    ).resolves.toBe(true);
  });

  it('does not flag Hono query after String() into a parameterized query', async () => {
    await expect(
      has(
        `app.get('/x', requireAuth, async (c) => { db.query('SELECT * FROM t WHERE q = $1', [String(c.req.query('q'))]); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });

  it('flags Koa ctx.request.body / ctx.query / ctx.params as taint', async () => {
    await expect(
      has(`router.post('/x', async (ctx) => { User.find(ctx.request.body); });`, 'SAST-NOSQLI-001'),
    ).resolves.toBe(true);
    await expect(
      has(`router.get('/x', async (ctx) => { db.query('SELECT ' + ctx.query.q); });`, 'SAST-SQLI-001'),
    ).resolves.toBe(true);
    await expect(
      has(`router.get('/x/:id', async (ctx) => { db.query('SELECT ' + ctx.params.id); });`, 'SAST-SQLI-001'),
    ).resolves.toBe(true);
  });

  it('does not flag Koa query after String() into a parameterized query', async () => {
    await expect(
      has(
        `router.get('/x', requireAuth, async (ctx) => { db.query('SELECT * FROM t WHERE q = $1', [String(ctx.query.q)]); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });

  it('flags AUTH on Next/Nest handlers without session/guards, not on the clean forms', async () => {
    await expect(
      has(`export async function GET() { db.query('SELECT 1'); }`, 'SAST-AUTH-001', 'app/api/x/route.ts'),
    ).resolves.toBe(true);
    await expect(
      has(
        `export async function GET() { const session = await auth(); db.query('SELECT 1'); }`,
        'SAST-AUTH-001',
        'app/api/x/route.ts',
      ),
    ).resolves.toBe(false);
    await expect(
      has(
        `class C {\n  @Get('/x')\n  list() { db.query('SELECT 1'); }\n}`,
        'SAST-AUTH-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(
        `class C {\n  @UseGuards(AuthGuard)\n  @Get('/x')\n  list() { db.query('SELECT 1'); }\n}`,
        'SAST-AUTH-001',
      ),
    ).resolves.toBe(false);
  });

  it('scans each vulnerable fixture and stays clean on the matching secure fixture', async () => {
    const nextV = await scanApp('next-vuln');
    expect(nextV.findings.some((f) => f.ruleId === 'SAST-NOSQLI-001')).toBe(true);
    expect(nextV.findings.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(nextV.findings.some((f) => f.ruleId === 'SAST-AUTH-001')).toBe(true);

    const nextC = await scanApp('next-clean');
    expect(nextC.findings.filter((f) => ['SAST-SQLI-001', 'SAST-NOSQLI-001', 'SAST-AUTH-001'].includes(f.ruleId))).toEqual(
      [],
    );

    const nestV = await scanApp('nest-vuln');
    expect(nestV.findings.some((f) => f.ruleId === 'SAST-NOSQLI-001' || f.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(nestV.findings.some((f) => f.ruleId === 'SAST-AUTH-001')).toBe(true);
    const nestC = await scanApp('nest-clean');
    expect(nestC.findings.filter((f) => ['SAST-SQLI-001', 'SAST-NOSQLI-001', 'SAST-AUTH-001'].includes(f.ruleId))).toEqual(
      [],
    );

    const honoV = await scanApp('hono-vuln');
    expect(honoV.findings.some((f) => f.ruleId === 'SAST-NOSQLI-001' || f.ruleId === 'SAST-SQLI-001')).toBe(true);
    const honoC = await scanApp('hono-clean');
    expect(honoC.findings.filter((f) => ['SAST-SQLI-001', 'SAST-NOSQLI-001', 'SAST-AUTH-001'].includes(f.ruleId))).toEqual(
      [],
    );

    const koaV = await scanApp('koa-vuln');
    expect(koaV.findings.some((f) => f.ruleId === 'SAST-NOSQLI-001' || f.ruleId === 'SAST-SQLI-001')).toBe(true);
    const koaC = await scanApp('koa-clean');
    expect(koaC.findings.filter((f) => ['SAST-SQLI-001', 'SAST-NOSQLI-001', 'SAST-AUTH-001'].includes(f.ruleId))).toEqual(
      [],
    );
  });

  it('lists every route in the framework fixtures', async () => {
    expect(await listed('next-vuln/app/api/items/route.ts')).toEqual(expect.arrayContaining(['GET /api/items', 'POST /api/items']));
    expect(await listed('next-vuln/app/actions.ts')).toEqual(expect.arrayContaining(['ACTION createItem']));
    expect(await listed('next-vuln/pages/api/legacy.ts')).toEqual(expect.arrayContaining(['ALL /api/legacy']));
    expect(await listed('next-clean/app/api/items/route.ts')).toEqual(expect.arrayContaining(['GET /api/items']));
    expect(await listed('nest-vuln/items.controller.ts')).toEqual(expect.arrayContaining(['GET /items', 'POST /items']));
    expect(await listed('nest-clean/items.controller.ts')).toEqual(expect.arrayContaining(['GET /items', 'POST /items']));
    expect(await listed('hono-vuln/index.ts')).toEqual(
      expect.arrayContaining(['GET /items', 'POST /items', 'GET /items/:id']),
    );
    expect(await listed('hono-clean/index.ts')).toEqual(expect.arrayContaining(['GET /items', 'POST /items']));
    expect(await listed('koa-vuln/index.ts')).toEqual(
      expect.arrayContaining(['GET /items', 'POST /items', 'GET /items/:id']),
    );
    expect(await listed('koa-clean/index.ts')).toEqual(expect.arrayContaining(['GET /items', 'POST /items']));
  });

  it('registers scan --experimental-frameworks', () => {
    const program = createProgram();
    const scanCmd = program.commands.find((c) => c.name() === 'scan');
    expect(scanCmd).toBeDefined();
    expect(scanCmd!.options.map((o) => o.long)).toContain('--experimental-frameworks');
  });

  it('koa and hono runtime adapters block SQLi without loading the scanner', async () => {
    const koaNext = (): Promise<void> => Promise.resolve();
    const koaCtx = {
      method: 'GET',
      path: '/q',
      query: { q: "' OR 1=1--" },
      status: 200,
      body: undefined as unknown,
    };
    await koaGuard({ mode: 'block' })(koaCtx, koaNext);
    expect(koaCtx.status).toBe(403);

    const hono = honoGuard({ mode: 'block' });
    const sent: unknown[] = [];
    const out = await hono(
      {
        req: { method: 'GET', path: '/q', query: () => ({ q: "' OR 1=1--" }) },
        json: (body: unknown, status?: number) => {
          sent.push(status, body);
          return body;
        },
      },
      (): Promise<void> => Promise.resolve(),
    );
    expect(sent[0]).toBe(403);
    expect(out).toEqual({ error: 'blocked', ruleId: 'RUNTIME-SQLI-001' });
  });
});
