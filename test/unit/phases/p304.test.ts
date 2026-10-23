import { afterEach, describe, expect, it } from 'vitest';

import { analyzeIpc, enabled, FLAG } from '../../../src/phases/p304.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 304 electron ipc', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeIpc("ipcMain.handle('open', (event, file) => { fs.readFile(file); });", { sandbox: true, nodeIntegration: false }).findings).toEqual([]);
  });

  it('drops basename and lowers confidence when the bridge is the only exposure', () => {
    process.env[FLAG] = '1';
    const open = analyzeIpc("contextBridge.exposeInMainWorld('api', { open() {} });\nipcMain.handle('open', (event, file) => { fs.readFile(file); });\nipcMain.handle('secret', (event, file) => { fs.readFile(file); });", { sandbox: true, nodeIntegration: false });
    expect(open.findings.find((finding) => finding.route === 'IPC open')).toMatchObject({ confidence: 'high', origin: 'renderer', witness: 'bridge' });
    expect(open.findings.find((finding) => finding.route === 'IPC secret')).toMatchObject({ confidence: 'low', witness: 'no bridge entry' });
    const integrated = analyzeIpc("ipcMain.handle('secret', (event, file) => { fs.readFile(file); });", { sandbox: true, nodeIntegration: true });
    expect(integrated.findings[0]?.confidence).toBe('high');
    const safe = analyzeIpc("ipcMain.handle('open', (event, file) => { fs.readFile(path.basename(file)); });", { sandbox: true, nodeIntegration: true });
    expect(safe.findings).toEqual([]);
    const emitted = analyzeIpc("ipcMain.emit('open', null, 'fixed');", { sandbox: false, nodeIntegration: false });
    expect(emitted.findings).toEqual([]);
  });

  it('records a computed bridge and the sink names that use a later argument', () => {
    process.env[FLAG] = '1';
    const result = analyzeIpc(`
      contextBridge.exposeInMainWorld('api');
      contextBridge.exposeInMainWorld('api', api);
      contextBridge.exposeInMainWorld('api', { open() {}, [key]: 1, ...rest });
      ipcMain.handle('open', (event, file) => { fs.readFileSync(file.name); exec(file); execSync(path.join(file)); open(file); (0, readFile)(file); readFile(...file); });
      ipcMain.on(channel, (event, file) => { readFile(file); });
      ipcMain.handle('noarg', (event) => { readFile('x'); });
      ipcMain.handle('literal', (event, file) => { readFile(1); });
      handle('x', (event, file) => { readFile(file); });
      ipcMain.handle('x', notFn);
    `, { sandbox: true, nodeIntegration: false }, { file: 'main.js' });
    expect(result.events.map((event) => event.reason)).toEqual(['computed expose', 'computed expose', 'computed expose']);
    expect(result.findings.find((finding) => finding.route === 'IPC open')).toMatchObject({ file: 'main.js', confidence: 'high', witness: 'bridge' });
    expect(result.findings.find((finding) => finding.route === 'IPC literal')).toBeUndefined();
    expect(result.findings.find((finding) => finding.route === 'IPC noarg')).toBeUndefined();
    expect(analyzeIpc('???', { sandbox: true, nodeIntegration: false }).findings).toEqual([]);
  });
});
