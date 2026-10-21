import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { electronEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_ELECTRON';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-electron-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_ELECTRON', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(electronEnabled()).toBe(false);
    process.env[FLAG] = 'true';
    expect(electronEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(electronEnabled()).toBe(true);
  });

  it('reports each unsafe webPreferences option, openExternal, and a remote window', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ devDependencies: { electron: '28.0.0' } }));
    await writeFile(
      join(cwd, 'prefs.js'),
      [
        'const win = new BrowserWindow({',
        '  webPreferences: {',
        '    nodeIntegration: true,',
        '    contextIsolation: false,',
        '    sandbox: false,',
        '    webSecurity: false,',
        '    allowRunningInsecureContent: true,',
        '  },',
        '});',
      ].join('\n'),
    );
    await writeFile(join(cwd, 'open.js'), 'shell.openExternal(url);\n');
    await writeFile(join(cwd, 'literal.js'), "shell.openExternal('https://example.com');\n");
    await writeFile(join(cwd, 'checked.js'), "if (String(url).startsWith('https:')) shell.openExternal(url);\n");
    await writeFile(join(cwd, 'remote.js'), "win.loadURL('https://remote.example');\n");
    await writeFile(join(cwd, 'guarded.js'), "win.loadURL('https://remote.example');\nwin.webContents.setWindowOpenHandler(() => ({}));\n");
    await writeFile(join(cwd, 'file.js'), "win.loadFile('index.html');\n");
    const result = await scan({ cwd, modules: ['config'], offline: true });
    const ids = (file: string, rule: string) => result.findings.filter((f) => f.file === file && f.ruleId === rule);
    expect(ids('prefs.js', 'CONFIG-ELECTRON-001')).toHaveLength(5);
    expect(ids('prefs.js', 'CONFIG-ELECTRON-001').every((f) => f.severity === 'high')).toBe(true);
    expect(ids('open.js', 'CONFIG-ELECTRON-002')).toHaveLength(1);
    expect(ids('literal.js', 'CONFIG-ELECTRON-002')).toHaveLength(0);
    expect(ids('checked.js', 'CONFIG-ELECTRON-002')).toHaveLength(0);
    expect(ids('remote.js', 'CONFIG-ELECTRON-003')).toHaveLength(1);
    expect(ids('remote.js', 'CONFIG-ELECTRON-003')[0]?.severity).toBe('medium');
    expect(ids('guarded.js', 'CONFIG-ELECTRON-003')).toHaveLength(0);
    expect(ids('file.js', 'CONFIG-ELECTRON-003')).toHaveLength(0);
  });

  it('stays quiet unless electron is installed, including via the lockfile', async () => {
    process.env[FLAG] = '1';
    const plain = await fixtureDir();
    await writeFile(join(plain, 'package.json'), JSON.stringify({ name: 'app' }));
    await writeFile(join(plain, 'main.js'), 'webPreferences: { nodeIntegration: true }\n');
    const locked = await fixtureDir();
    await writeFile(join(locked, 'package.json'), JSON.stringify({ name: 'app' }));
    await writeFile(
      join(locked, 'package-lock.json'),
      JSON.stringify({
        name: 'app',
        lockfileVersion: 2,
        packages: { '': {}, 'node_modules/electron': { version: '28.0.0' } },
      }),
    );
    await writeFile(join(locked, 'main.js'), 'const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n');
    const without = await scan({ cwd: plain, modules: ['config'], offline: true });
    const withLock = await scan({ cwd: locked, modules: ['config'], offline: true });
    expect(without.findings.filter((f) => f.ruleId.startsWith('CONFIG-ELECTRON'))).toEqual([]);
    expect(withLock.findings.some((f) => f.ruleId === 'CONFIG-ELECTRON-001')).toBe(true);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ devDependencies: { electron: '28.0.0' } }));
    await writeFile(join(cwd, 'main.js'), 'const win = new BrowserWindow({ webPreferences: { sandbox: false } });\n');
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['config'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['config'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['config'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['config'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['config'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('CONFIG-ELECTRON-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { electron: '28.0.0' } }));
    await writeFile(join(cwd, 'main.js'), 'const win = new BrowserWindow({ webPreferences: { webSecurity: false } });\n');
    const first = await scan({ cwd, modules: ['config'], offline: true });
    const second = await scan({ cwd, modules: ['config'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'CONFIG-ELECTRON-001')).toBe(true);
  });
});
