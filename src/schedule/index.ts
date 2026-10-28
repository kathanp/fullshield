import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { homedir, userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { writeLastScan } from '../core/lastScan.js';
import { raise } from '../core/raise.js';
import type { scan } from '../core/engine.js';
import { renderMarkdownReport } from '../reporters/markdown.js';

const REPORT_DIR = 'fullShieldReport';
const KEEP_REPORTS = 60;
const INTERVAL_HOURS = 2;

const REPORT_NAME = /^fullShieldReport_\d{8}_\d{4}\.md$/;

export interface ScheduleProcess {
  status: number;
  stdout: string;
  stderr: string;
}

export interface ScheduleHost {
  platform: NodeJS.Platform;
  home: string;
  execPath: string;
  cliPath: string;
  uid: number;
  readText(path: string): Promise<string | undefined>;
  writeText(path: string, body: string): Promise<void>;
  removeFile(path: string): Promise<void>;
  exec(file: string, args: readonly string[], input?: string): Promise<ScheduleProcess>;
}

export interface ScheduleInstallResult {
  gitignore: 'added' | 'present';
  reportsDir: string;
}

export interface ScheduleRunResult {
  file: string;
  removed: number;
}

type ScheduleAction = 'install' | 'uninstall' | 'status';

function isEnoent(error: unknown): boolean {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return false;
  }
  return error.code === 'ENOENT';
}

function failSchedule(action: ScheduleAction, detail: string): never {
  const text = detail.trim().replace(/\s+/g, ' ').slice(0, 200);
  const suffix = text === '' ? '' : `: ${text}`;
  if (action === 'install') {
    raise(`schedule install could not register the timer${suffix}`);
  }
  if (action === 'uninstall') {
    raise(`schedule uninstall could not remove the timer${suffix}`);
  }
  raise(`schedule status could not read the timer${suffix}`);
}

function assertSingleLine(value: string): void {
  if (value.includes('\n') || value.includes('\r')) {
    failSchedule('install', 'path');
  }
}

function projectHash(cwd: string): string {
  return createHash('sha256').update(cwd).digest('hex').slice(0, 12);
}

export function reportFileName(now: Date): string {
  const pad = (value: number): string => String(value).padStart(2, '0');
  const stamp = [
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`,
    `${pad(now.getHours())}${pad(now.getMinutes())}`,
  ].join('_');
  return `fullShieldReport_${stamp}.md`;
}

export function withReportGitignore(existing: string | undefined): { text: string; changed: boolean } {
  if (existing === undefined) {
    return { text: `${REPORT_DIR}/\n`, changed: true };
  }
  const present = existing.split(/\r?\n/).some((line) => {
    const trimmed = line.trim();
    return trimmed === `${REPORT_DIR}/` || trimmed === REPORT_DIR;
  });
  if (present) {
    return { text: existing, changed: false };
  }
  const prefix = existing.endsWith('\n') ? existing : `${existing}\n`;
  return { text: `${prefix}${REPORT_DIR}/\n`, changed: true };
}

function namesToDelete(names: readonly string[], written: string): string[] {
  const older = names.filter((name) => REPORT_NAME.test(name) && name !== written).sort();
  const extras = older.length + 1 - KEEP_REPORTS;
  if (extras <= 0) {
    return [];
  }
  return older.slice(0, extras);
}

async function assertProjectDir(cwd: string): Promise<string> {
  const resolved = resolve(cwd);
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(resolved);
  } catch {
    raise(`schedule path is not a directory: ${resolved}`);
  }
  if (!info.isDirectory()) {
    raise(`schedule path is not a directory: ${resolved}`);
  }
  return resolved;
}

async function ensureGitignore(cwd: string): Promise<'added' | 'present'> {
  const path = join(cwd, '.gitignore');
  let existing: string | undefined;
  try {
    existing = await readFile(path, 'utf8');
  } catch (error) {
    if (!isEnoent(error)) {
      failSchedule('install', 'gitignore');
    }
  }
  const next = withReportGitignore(existing);
  if (!next.changed) {
    return 'present';
  }
  await writeFile(path, next.text, 'utf8');
  return 'added';
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function xmlEscape(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function runCommand(host: ScheduleHost, cwd: string): string {
  return [
    shellQuote(host.execPath),
    shellQuote(host.cliPath),
    'schedule',
    'run',
    shellQuote(cwd),
  ].join(' ');
}

function marker(kind: 'BEGIN' | 'END', hash: string): string {
  return `# fullshield-schedule ${kind} ${hash}`;
}

function removeCronBlock(crontab: string, hash: string): { text: string; removed: boolean } {
  const lines = crontab.split('\n');
  const start = lines.indexOf(marker('BEGIN', hash));
  const stop = lines.indexOf(marker('END', hash));
  if (start === -1 || stop < start) {
    return { text: crontab, removed: false };
  }
  const next = [...lines.slice(0, start), ...lines.slice(stop + 1)];
  return { text: next.join('\n'), removed: true };
}

function upsertCronBlock(crontab: string, hash: string, command: string): string {
  const stripped = removeCronBlock(crontab, hash).text;
  const block = `${marker('BEGIN', hash)}\n${command}\n${marker('END', hash)}\n`;
  if (stripped.trim() === '') {
    return block;
  }
  const base = stripped.endsWith('\n') ? stripped : `${stripped}\n`;
  return `${base}${block}`;
}

function cronLine(host: ScheduleHost, cwd: string): string {
  return `0 */${INTERVAL_HOURS} * * * ${runCommand(host, cwd)}`;
}

async function readCrontab(host: ScheduleHost, action: ScheduleAction): Promise<string> {
  const result = await host.exec('crontab', ['-l']);
  if (result.status === 0) {
    return result.stdout;
  }
  const detail = `${result.stdout}\n${result.stderr}`;
  if (result.stdout.trim() === '' && /no crontab/i.test(detail)) {
    return '';
  }
  if (result.stdout.trim() === '' && result.stderr.trim() === '') {
    return '';
  }
  failSchedule(action, result.stderr);
}

async function writeCrontab(host: ScheduleHost, body: string, action: ScheduleAction): Promise<void> {
  const result = await host.exec('crontab', ['-'], body);
  if (result.status !== 0) {
    failSchedule(action, result.stderr);
  }
}

async function installCron(cwd: string, host: ScheduleHost): Promise<void> {
  const hash = projectHash(cwd);
  const current = await readCrontab(host, 'install');
  await writeCrontab(host, upsertCronBlock(current, hash, cronLine(host, cwd)), 'install');
}

function calendarEntries(): string {
  const entries: string[] = [];
  for (let hour = 0; hour < 24; hour += INTERVAL_HOURS) {
    entries.push(
      [
        '    <dict>',
        '      <key>Hour</key>',
        `      <integer>${hour}</integer>`,
        '      <key>Minute</key>',
        '      <integer>0</integer>',
        '    </dict>',
      ].join('\n'),
    );
  }
  return entries.join('\n');
}

function plistBody(host: ScheduleHost, cwd: string, label: string): string {
  const args = [host.execPath, host.cliPath, 'schedule', 'run', cwd]
    .map((part) => `    <string>${xmlEscape(part)}</string>`)
    .join('\n');
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<plist version="1.0">',
    '<dict>',
    '  <key>Label</key>',
    `  <string>${xmlEscape(label)}</string>`,
    '  <key>ProgramArguments</key>',
    '  <array>',
    args,
    '  </array>',
    '  <key>StartCalendarInterval</key>',
    '  <array>',
    calendarEntries(),
    '  </array>',
    '  <key>WorkingDirectory</key>',
    `  <string>${xmlEscape(cwd)}</string>`,
    '</dict>',
    '</plist>',
    '',
  ].join('\n');
}

function launchAgentPath(host: ScheduleHost, label: string): string {
  return join(host.home, 'Library', 'LaunchAgents', `${label}.plist`);
}

function timerMissing(result: ScheduleProcess): boolean {
  return /could not find|no such|not found/i.test(`${result.stderr}\n${result.stdout}`);
}

async function installLaunchd(cwd: string, host: ScheduleHost): Promise<void> {
  const label = `com.fullshield.schedule.${projectHash(cwd)}`;
  const plist = launchAgentPath(host, label);
  await host.writeText(plist, plistBody(host, cwd, label));
  const domain = `gui/${host.uid}`;
  await host.exec('launchctl', ['bootout', `${domain}/${label}`]);
  const loaded = await host.exec('launchctl', ['bootstrap', domain, plist]);
  if (loaded.status !== 0) {
    failSchedule('install', loaded.stderr);
  }
}

function taskName(cwd: string): string {
  return `FullShield-${projectHash(cwd)}`;
}

async function installWindows(cwd: string, host: ScheduleHost): Promise<void> {
  const created = await host.exec('schtasks', [
    '/Create',
    '/F',
    '/TN',
    taskName(cwd),
    '/SC',
    'HOURLY',
    '/MO',
    String(INTERVAL_HOURS),
    '/ST',
    '00:00',
    '/TR',
    runCommand(host, cwd),
  ]);
  if (created.status !== 0) {
    failSchedule('install', created.stderr);
  }
}

async function installTimer(cwd: string, host: ScheduleHost): Promise<void> {
  assertSingleLine(cwd);
  assertSingleLine(host.execPath);
  assertSingleLine(host.cliPath);
  if (host.execPath.trim() === '' || host.cliPath.trim() === '') {
    failSchedule('install', 'node');
  }
  if (host.platform === 'darwin') {
    await installLaunchd(cwd, host);
    return;
  }
  if (host.platform === 'win32') {
    await installWindows(cwd, host);
    return;
  }
  await installCron(cwd, host);
}

async function cronInstalled(host: ScheduleHost, hash: string): Promise<boolean> {
  const result = await host.exec('crontab', ['-l']);
  if (result.status === 0) {
    return result.stdout.includes(marker('BEGIN', hash));
  }
  const detail = `${result.stdout}\n${result.stderr}`;
  const empty = result.stdout.trim() === '';
  if (empty && (/no crontab/i.test(detail) || result.stderr.trim() === '')) {
    return false;
  }
  failSchedule('status', result.stderr);
}

async function timerInstalled(cwd: string, host: ScheduleHost): Promise<boolean> {
  const hash = projectHash(cwd);
  if (host.platform === 'darwin') {
    const text = await host.readText(launchAgentPath(host, `com.fullshield.schedule.${hash}`));
    return text !== undefined;
  }
  if (host.platform === 'win32') {
    const result = await host.exec('schtasks', ['/Query', '/TN', taskName(cwd), '/FO', 'LIST']);
    return result.status === 0;
  }
  return cronInstalled(host, hash);
}

async function uninstallCron(cwd: string, host: ScheduleHost): Promise<boolean> {
  const current = await readCrontab(host, 'uninstall');
  const next = removeCronBlock(current, projectHash(cwd));
  if (!next.removed) {
    return false;
  }
  await writeCrontab(host, next.text, 'uninstall');
  return true;
}

async function uninstallLaunchd(cwd: string, host: ScheduleHost): Promise<boolean> {
  const label = `com.fullshield.schedule.${projectHash(cwd)}`;
  const plist = launchAgentPath(host, label);
  const existing = await host.readText(plist);
  if (existing === undefined) {
    return false;
  }
  const stopped = await host.exec('launchctl', ['bootout', `gui/${host.uid}/${label}`]);
  if (stopped.status !== 0 && !timerMissing(stopped)) {
    failSchedule('uninstall', stopped.stderr);
  }
  await host.removeFile(plist);
  return true;
}

async function uninstallWindows(cwd: string, host: ScheduleHost): Promise<boolean> {
  const name = taskName(cwd);
  const query = await host.exec('schtasks', ['/Query', '/TN', name, '/FO', 'LIST']);
  if (query.status !== 0) {
    return false;
  }
  const removed = await host.exec('schtasks', ['/Delete', '/F', '/TN', name]);
  if (removed.status !== 0) {
    failSchedule('uninstall', removed.stderr);
  }
  return true;
}

async function uninstallTimer(cwd: string, host: ScheduleHost): Promise<boolean> {
  if (host.platform === 'darwin') {
    return uninstallLaunchd(cwd, host);
  }
  if (host.platform === 'win32') {
    return uninstallWindows(cwd, host);
  }
  return uninstallCron(cwd, host);
}

async function countReports(cwd: string): Promise<number> {
  let names: string[];
  try {
    names = await readdir(join(cwd, REPORT_DIR));
  } catch (error) {
    if (isEnoent(error)) {
      return 0;
    }
    failSchedule('status', 'reports');
  }
  return names.filter((name) => REPORT_NAME.test(name)).length;
}

function execCommand(file: string, args: readonly string[], input?: string): Promise<ScheduleProcess> {
  const result = spawnSync(file, [...args], { encoding: 'utf8', windowsHide: true, input });
  const stderr = result.stderr === '' && result.error !== undefined ? result.error.message : result.stderr;
  const status = typeof result.status === 'number' ? result.status : 1;
  return Promise.resolve({ status, stdout: result.stdout, stderr });
}

async function readOptionalText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if (isEnoent(error)) {
      return undefined;
    }
    failSchedule('status', 'timer file');
  }
}

async function writeTextFile(path: string, body: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, body, 'utf8');
}

async function removeOptionalFile(path: string): Promise<void> {
  await rm(path, { force: true });
}

export function createScheduleHost(cliPath: string): ScheduleHost {
  return {
    platform: process.platform,
    home: homedir(),
    execPath: process.execPath,
    cliPath,
    uid: userInfo().uid,
    readText: readOptionalText,
    writeText: writeTextFile,
    removeFile: removeOptionalFile,
    exec: execCommand,
  };
}

export async function installSchedule(cwd: string, host: ScheduleHost): Promise<ScheduleInstallResult> {
  const project = await assertProjectDir(cwd);
  await mkdir(join(project, REPORT_DIR), { recursive: true });
  const gitignore = await ensureGitignore(project);
  await installTimer(project, host);
  return { gitignore, reportsDir: REPORT_DIR };
}

export async function runSchedule(
  cwd: string,
  now: Date,
  scanProject: typeof scan,
): Promise<ScheduleRunResult> {
  const project = await assertProjectDir(cwd);
  const dir = join(project, REPORT_DIR);
  await mkdir(dir, { recursive: true });
  const result = await scanProject({ cwd: project });
  const name = reportFileName(now);
  await writeFile(join(dir, name), renderMarkdownReport(result), 'utf8');
  const removed = namesToDelete(await readdir(dir), name);
  for (const file of removed) {
    await rm(join(dir, file), { force: true });
  }
  await writeLastScan(project, result);
  return { file: `${REPORT_DIR}/${name}`, removed: removed.length };
}

export async function scheduleStatus(cwd: string, host: ScheduleHost): Promise<{ installed: boolean; reports: number }> {
  const project = await assertProjectDir(cwd);
  const installed = await timerInstalled(project, host);
  const reports = await countReports(project);
  return { installed, reports };
}

export async function uninstallSchedule(cwd: string, host: ScheduleHost): Promise<boolean> {
  const project = await assertProjectDir(cwd);
  return uninstallTimer(project, host);
}
