import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { browserEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_BROWSER';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-browser-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_BROWSER', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(browserEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(browserEnabled()).toBe(true);
  });

  it('reports DOM sinks, HTML bindings, postMessage, and localStorage tokens', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'components'), { recursive: true });
    await writeFile(
      join(cwd, 'components', 'dom.js'),
      [
        'el.innerHTML = location.hash;',
        'document.write(document.URL);',
        '$(location.search);',
        "setTimeout('run(' + location.href + ')');",
        'const params = new URLSearchParams(location.search);',
        "el.innerHTML = params.get('q');",
      ].join('\n'),
    );
    await writeFile(join(cwd, 'components', 'href.js'), "if (String(location.href).startsWith('https:')) el.href = location.href;\n");
    await writeFile(join(cwd, 'components', 'view.js'), 'const view = { dangerouslySetInnerHTML: { __html: name } };\n');
    await writeFile(join(cwd, 'components', 'literal.js'), "const view = { dangerouslySetInnerHTML: { __html: '<b>ok</b>' } };\n");
    await writeFile(
      join(cwd, 'components', 'clean.js'),
      'const view = { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(name) } };\n',
    );
    await writeFile(join(cwd, 'components', 'App.vue'), '<div v-html="name"></div>\n');
    await writeFile(
      join(cwd, 'components', 'message.js'),
      "'use client';\nwindow.addEventListener('message', (event) => { el.innerHTML = event.data; });\nparent.postMessage(accessToken, '*');\n",
    );
    await writeFile(
      join(cwd, 'components', 'origin.js'),
      "'use client';\nwindow.addEventListener('message', (event) => { if (event.origin === 'https://app.example') use(event.data); });\n",
    );
    await writeFile(join(cwd, 'components', 'store.js'), "'use client';\nlocalStorage.setItem('accessToken', value);\n");
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const ids = (file: string, rule: string) => result.findings.filter((f) => f.file === file && f.ruleId === rule);
    expect(ids('components/dom.js', 'SAST-DOMXSS-001').length).toBeGreaterThanOrEqual(3);
    expect(ids('components/href.js', 'SAST-DOMXSS-001')).toHaveLength(0);
    expect(ids('components/view.js', 'SAST-REACT-001')).toHaveLength(1);
    expect(ids('components/literal.js', 'SAST-REACT-001')).toHaveLength(0);
    expect(ids('components/clean.js', 'SAST-REACT-001')).toHaveLength(0);
    expect(ids('components/App.vue', 'SAST-REACT-001')).toHaveLength(1);
    expect(ids('components/message.js', 'SAST-POSTMSG-001').length).toBeGreaterThanOrEqual(2);
    expect(ids('components/origin.js', 'SAST-POSTMSG-001')).toHaveLength(0);
    expect(ids('components/store.js', 'SAST-TOKENSTORE-001')).toMatchObject([{ severity: 'low' }]);
  });

  it('does not run server taint rules on browser sources, and still runs them on use server', async () => {
    const sql = "db.query('SELECT ' + req.query.id);\n";
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'components'), { recursive: true });
    await mkdir(join(cwd, 'app'), { recursive: true });
    await writeFile(join(cwd, 'components', 'widget.js'), `'use client';\n${sql}`);
    await writeFile(join(cwd, 'app', 'action.js'), `'use server';\n${sql}`);
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ name: 'app', browser: 'dist/app.js' }));
    await writeFile(join(cwd, 'server.js'), sql);
    delete process.env[FLAG];
    const off = await scan({ cwd, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const on = await scan({ cwd, modules: ['sast'], offline: true });
    const sqli = (findings: typeof on.findings, file: string) => findings.filter((f) => f.ruleId === 'SAST-SQLI-001' && f.file === file);
    expect(sqli(off.findings, 'components/widget.js').length).toBeGreaterThan(0);
    expect(sqli(on.findings, 'components/widget.js')).toEqual([]);
    expect(sqli(on.findings, 'app/action.js').length).toBeGreaterThan(0);
    expect(sqli(off.findings, 'server.js').length).toBeGreaterThan(0);
    expect(sqli(on.findings, 'server.js')).toEqual([]);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'components'), { recursive: true });
    await writeFile(join(cwd, 'components', 'dom.js'), 'el.innerHTML = location.hash;\n');
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-DOMXSS-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'pages'), { recursive: true });
    await writeFile(join(cwd, 'pages', 'home.js'), 'el.outerHTML = document.referrer;\n');
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-DOMXSS-001')).toBe(true);
  });
});
