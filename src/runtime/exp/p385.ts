/**
 * Phase 385. cmd.exe metacharacters.
 * Off unless FULLSHIELD_EXPERIMENTAL_CMDTOK=1.
 * The cmd tokenizer is not selected for execFile.
 * Vectors run on every OS; this module does not spawn a process.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CMDTOK';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const CMD_META = /[%^&|\n\r"'"]/;

export function cmdHole(hole: string): boolean {
  return CMD_META.test(hole);
}

/** POSIX does not treat a bare percent sign as a metacharacter. */
export function posixHole(hole: string): boolean {
  return /[;&|`$<>\n]/.test(hole);
}

export interface CommandCall {
  program: string;
  shell: boolean;
  args: readonly string[];
}

export function commandEvent(call: CommandCall): boolean {
  if (!enabled()) {
    return false;
  }
  const winShell = call.shell || (call.program.toLowerCase() === 'cmd.exe' && call.args.includes('/c'));
  if (call.program === 'execFile' && !call.shell) {
    return false;
  }
  const hole = call.args[call.args.length - 1] ?? '';
  if (winShell) {
    return cmdHole(hole);
  }
  return posixHole(hole);
}
