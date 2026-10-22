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
});
