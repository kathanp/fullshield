/**
 * Phase 386. Windows path forms.
 * Off unless FULLSHIELD_EXPERIMENTAL_WINPATH=1.
 * The static domain reports on every OS. The hook rejects only in win32 mode.
 * This module does not spawn a process.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_WINPATH';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type WinForm = 'unc' | 'device' | 'drive-relative' | 'ads' | 'short';

export interface WinPathFinding {
  ruleId: 'SAST-PATH-001';
  form: WinForm;
  message: string;
}

export function classifyWindowsPath(segment: string): WinForm | null {
  if (segment.startsWith('\\\\?\\') || segment.startsWith('\\\\.\\')) {
    return 'device';
  }
  if (segment.startsWith('\\\\')) {
    return 'unc';
  }
  if (/^[A-Za-z]:[^\\/]/.test(segment)) {
    return 'drive-relative';
  }
  if (/^[A-Za-z0-9._-]{1,8}~\d/.test(segment)) {
    return 'short';
  }
  if (/^[^:\\]+:[^\\/]+$/.test(segment) && !/^[A-Za-z]:/.test(segment)) {
    return 'ads';
  }
  return null;
}

export function staticWindowsPath(segment: string, tainted: boolean, basename: boolean): WinPathFinding | null {
  if (!enabled() || !tainted || basename) {
    return null;
  }
  const form = classifyWindowsPath(segment);
  if (form === null) {
    return null;
  }
  return {
    ruleId: 'SAST-PATH-001',
    form,
    message: `The form is a Windows path (${form}).`,
  };
}

function normalizeWin(value: string): string {
  return value.replaceAll('/', '\\');
}

/** POSIX mode does not emit these forms. Win32 rejects a path that leaves the base. */
export function hookRejects(base: string, resolved: string, os: 'win32' | 'posix'): boolean {
  if (!enabled() || os === 'posix') {
    return false;
  }
  const root = normalizeWin(base);
  const path = normalizeWin(resolved);
  const prefix = root.endsWith('\\') ? root : `${root}\\`;
  if (path === root || path.startsWith(prefix)) {
    return false;
  }
  return classifyWindowsPath(path) !== null || path.startsWith('\\\\') || /^[A-Za-z]:/.test(path);
}
