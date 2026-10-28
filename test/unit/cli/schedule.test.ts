import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult, scan } from '../../../src/core/engine.js';
import { MODULE_NAMES } from '../../../src/core/finding.js';
import {
  createScheduleHost,
  installSchedule,
  reportFileName,
  runSchedule,
  scheduleStatus,
  uninstallSchedule,
  withReportGitignore,
  type ScheduleHost,
  type ScheduleProcess,
} from '../../../src/schedule/index.js';

const dirs: string[] = [];

beforeEach(() => {
  process.exitCode = undefined;
});

afterEach(async () => {
  process.exitCode = undefined;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function tempProject(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-schedule-'));
  dirs.push(dir);
  return dir;
}

function reportScan(cwd: string, high: boolean): ScanResult {
  return {
    findings: high
      ? [
        {
          id: 'abc',
          ruleId: 'CONFIG-HELMET-001',
          module: 'config',
          title: 'Helmet',
          severity: 'high',
          confidence: 'high',
          message: 'missing helmet',
          remediation: 'add helmet',
        },
      ]
      : [],
    summary: {
      total: high ? 1 : 0,
      bySeverity: { info: 0, low: 0, medium: 0, high: high ? 1 : 0, critical: 0 },
    },
    metadata: {
      version: '3.0.0',
      startedAt: '2026-10-28T19:00:00.000Z',
      durationMs: 1,
      cwd,
      filesScanned: 0,
      modulesRequested: MODULE_NAMES,
      modulesRun: MODULE_NAMES,
    },
    config: DEFAULT_CONFIG,
  };
}

const scanProject: typeof scan = (options = {}) => Promise.resolve(reportScan(options.cwd ?? '.', true));
const cleanProject: typeof scan = (options = {}) => Promise.resolve(reportScan(options.cwd ?? '.', false));

interface MemoryHost extends ScheduleHost {
  files: Map<string, string>;
  commands: string[][];
  crontab: () => string;
  failNext: (stderr: string) => void;
}

function memoryHost(platform: NodeJS.Platform): MemoryHost {
  const files = new Map<string, string>();
  const commands: string[][] = [];
  const state = { crontab: '', task: false, fail: '' };
  const ok: ScheduleProcess = { status: 0, stdout: '', stderr: '' };
  const host: MemoryHost = {
    platform,
    home: '/tmp/fullshield-home',
    execPath: '/usr/local/bin/node',
    cliPath: '/usr/local/lib/fullshield.js',
    uid: 501,
    files,
    commands,
    crontab: () => state.crontab,
    failNext: (stderr: string) => {
      state.fail = stderr;
    },
    readText(path: string) {
      return Promise.resolve(files.get(path));
    },
    writeText(path: string, body: string) {
      files.set(path, body);
      return Promise.resolve();
    },
    removeFile(path: string) {
      files.delete(path);
      return Promise.resolve();
    },
    exec(file: string, args: readonly string[], input?: string) {
      commands.push([file, ...args]);
      if (state.fail !== '') {
        const stderr = state.fail;
        state.fail = '';
        return Promise.resolve({ status: 1, stdout: '', stderr });
      }
      if (file === 'crontab' && args[0] === '-l') {
        if (state.crontab === '') {
          return Promise.resolve({ status: 1, stdout: '', stderr: 'no crontab for user' });
        }
        return Promise.resolve({ status: 0, stdout: state.crontab, stderr: '' });
      }
      if (file === 'crontab' && args[0] === '-') {
        state.crontab = input ?? '';
        return Promise.resolve(ok);
      }
      if (file === 'schtasks' && args.includes('/Create')) {
        state.task = true;
        return Promise.resolve(ok);
      }
      if (file === 'schtasks' && args.includes('/Query')) {
        return Promise.resolve(state.task ? ok : { status: 1, stdout: '', stderr: 'not found' });
      }
      if (file === 'schtasks' && args.includes('/Delete')) {
        state.task = false;
        return Promise.resolve(ok);
      }
      return Promise.resolve(ok);
    },
  };
  return host;
}

describe('schedule reports', () => {
  it('names a report with the local date and minute', () => {
    expect(reportFileName(new Date(2026, 9, 28, 14, 5, 9))).toBe('fullShieldReport_20261028_1405.md');
  });

  it('adds the report folder to gitignore once', () => {
    expect(withReportGitignore(undefined)).toEqual({ text: 'fullShieldReport/\n', changed: true });
    const existing = 'node_modules/\n.env\n';
    const added = withReportGitignore(existing);
    expect(added.changed).toBe(true);
    expect(added.text).toBe('node_modules/\n.env\nfullShieldReport/\n');
    expect(withReportGitignore(added.text).changed).toBe(false);
    expect(withReportGitignore('fullShieldReport\n').changed).toBe(false);
  });

  it('writes one dated report, keeps 60, and leaves other files', async () => {
    const cwd = await tempProject();
    const folder = join(cwd, 'fullShieldReport');
    await mkdir(folder);
    await writeFile(join(folder, 'notes.txt'), 'keep');
    for (let index = 0; index < 60; index += 1) {
      const name = `fullShieldReport_20260101_${String(index).padStart(4, '0')}.md`;
      await writeFile(join(folder, name), 'old');
    }
    const written = await runSchedule(cwd, new Date(2026, 9, 28, 14, 0, 0), scanProject);
    expect(written.file).toBe('fullShieldReport/fullShieldReport_20261028_1400.md');
    expect(written.removed).toBe(1);
    const body = await readFile(join(cwd, written.file), 'utf8');
    expect(body).toContain('CONFIG-HELMET-001');
    expect(await readFile(join(folder, 'notes.txt'), 'utf8')).toBe('keep');
    await expect(stat(join(folder, 'fullShieldReport_20260101_0000.md'))).rejects.toThrow();
    const gitignore = await stat(join(cwd, '.gitignore')).then(() => true, () => false);
    expect(gitignore).toBe(false);
  });

  it('installs a crontab entry and gitignores the folder once', async () => {
    const cwd = await tempProject();
    const host = memoryHost('linux');
    host.files.clear();
    const first = await installSchedule(cwd, host);
    expect(first.gitignore).toBe('added');
    expect(host.crontab()).toContain('# fullshield-schedule BEGIN');
    expect(host.crontab()).toContain('schedule run');
    expect(host.crontab()).toContain('*/2');
    const again = await installSchedule(cwd, host);
    expect(again.gitignore).toBe('present');
    expect(host.crontab().match(/fullshield-schedule BEGIN/g)).toHaveLength(1);
    const gitignore = await readFile(join(cwd, '.gitignore'), 'utf8');
    expect(gitignore.match(/fullShieldReport\//g)).toHaveLength(1);
    const status = await scheduleStatus(cwd, host);
    expect(status.installed).toBe(true);
    expect(await uninstallSchedule(cwd, host)).toBe(true);
    expect((await scheduleStatus(cwd, host)).installed).toBe(false);
    expect(await uninstallSchedule(cwd, host)).toBe(false);
  });

  it('keeps an existing crontab line and quotes a path', async () => {
    const cwd = await tempProject();
    const odd = join(cwd, "a'b");
    await mkdir(odd);
    const host = memoryHost('linux');
    await host.exec('crontab', ['-'], '0 1 * * * echo keep\n');
    await installSchedule(odd, host);
    expect(host.crontab()).toContain('echo keep');
    expect(host.crontab()).toContain(`'\\''`);
    expect(host.crontab().match(/fullshield-schedule BEGIN/g)).toHaveLength(1);
  });

  it('writes a LaunchAgent every two hours', async () => {
    const cwd = await tempProject();
    const odd = join(cwd, "a&b'c");
    await mkdir(odd);
    const host = memoryHost('darwin');
    await installSchedule(odd, host);
    const plist = [...host.files.values()][0] ?? '';
    expect(plist).toContain('<integer>0</integer>');
    expect(plist).toContain('<integer>22</integer>');
    expect(plist).toContain('&amp;');
    expect(plist).toContain('&apos;');
    expect(host.commands.some((command) => command[0] === 'launchctl' && command[1] === 'bootstrap')).toBe(true);
    expect((await scheduleStatus(odd, host)).installed).toBe(true);
    expect(await uninstallSchedule(odd, host)).toBe(true);
    expect(host.files.size).toBe(0);
  });

  it('registers a Windows task every two hours', async () => {
    const cwd = await tempProject();
    const host = memoryHost('win32');
    expect((await scheduleStatus(cwd, host)).installed).toBe(false);
    await installSchedule(cwd, host);
    const create = host.commands.find((command) => command.includes('/Create'));
    expect(create).toContain('HOURLY');
    expect(create).toContain('2');
    expect((await scheduleStatus(cwd, host)).installed).toBe(true);
    expect(await uninstallSchedule(cwd, host)).toBe(true);
    expect((await scheduleStatus(cwd, host)).installed).toBe(false);
  });

  it('reads and writes timer files through the real host without registering one', async () => {
    const cwd = await tempProject();
    const host = createScheduleHost(process.execPath);
    expect(host.platform).toBe(process.platform);
    expect(host.execPath).toBe(process.execPath);
    const note = join(cwd, 'note.txt');
    expect(await host.readText(note)).toBeUndefined();
    await host.writeText(note, 'hi');
    expect(await host.readText(note)).toBe('hi');
    await host.removeFile(note);
    const ok = await host.exec(process.execPath, ['-e', 'process.stdout.write("ok")']);
    expect(ok).toMatchObject({ status: 0, stdout: 'ok' });
    const failed = await host.exec(process.execPath, ['-e', 'process.exit(3)']);
    expect(failed.status).toBe(3);
  });

  it('refuses a path that is not a directory and a timer that cannot be registered', async () => {
    const cwd = await tempProject();
    const file = join(cwd, 'file.txt');
    await writeFile(file, 'x');
    await expect(installSchedule(file, memoryHost('linux'))).rejects.toThrow(/not a directory/);
    const host = memoryHost('linux');
    host.failNext('permission denied');
    await expect(installSchedule(cwd, host)).rejects.toThrow(/could not register the timer/);
    const darwin = memoryHost('darwin');
    await installSchedule(cwd, darwin);
    darwin.failNext('permission denied');
    await expect(uninstallSchedule(cwd, darwin)).rejects.toThrow(/could not remove the timer/);
    const windows = memoryHost('win32');
    windows.failNext('access denied');
    await expect(installSchedule(cwd, windows)).rejects.toThrow(/could not register the timer/);
  });
});

describe('schedule CLI', () => {
  it('scan does not create the report folder or edit gitignore', async () => {
    const cwd = await tempProject();
    await writeFile(join(cwd, '.gitignore'), 'node_modules/\n');
    const out: string[] = [];
    const program = createProgram({
      out: (text) => out.push(text),
      err: () => undefined,
      scan: cleanProject,
    });
    await program.parseAsync(['node', 'fullshield', 'scan', cwd, '--json']);
    expect(out.join('\n')).toContain('"findings"');
    await expect(stat(join(cwd, 'fullShieldReport'))).rejects.toThrow();
    expect(await readFile(join(cwd, '.gitignore'), 'utf8')).toBe('node_modules/\n');
    expect(process.exitCode).toBeUndefined();
  });

  it('schedule run writes the report and does not fail on a high finding', async () => {
    const cwd = await tempProject();
    const lines: string[] = [];
    const program = createProgram({
      out: (text) => lines.push(text),
      err: () => undefined,
      scan: scanProject,
    });
    await program.parseAsync(['node', 'fullshield', 'schedule', 'run', cwd]);
    expect(lines.join('\n')).toContain('fullShieldReport/fullShieldReport_');
    expect(process.exitCode).toBeUndefined();
    expect(await readFile(join(cwd, '.fullshield', 'last-scan.json'), 'utf8')).toContain('CONFIG-HELMET-001');
  });

  it('schedule install uses the injected host', async () => {
    const cwd = await tempProject();
    const host = memoryHost('linux');
    const lines: string[] = [];
    const program = createProgram({
      out: (text) => lines.push(text),
      err: () => undefined,
      scheduleHost: host,
    });
    await program.parseAsync(['node', 'fullshield', 'schedule', 'install', cwd]);
    expect(lines.join('\n')).toContain('keeps 60');
    expect(await readFile(join(cwd, '.gitignore'), 'utf8')).toContain('fullShieldReport/');
    await program.parseAsync(['node', 'fullshield', 'schedule', 'status', cwd]);
    expect(lines.join('\n')).toContain('schedule installed');
    await program.parseAsync(['node', 'fullshield', 'schedule', 'uninstall', cwd]);
    expect(lines.join('\n')).toContain('schedule removed');
  });
});
