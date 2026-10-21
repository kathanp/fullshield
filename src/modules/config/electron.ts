import { makeFindingId, type Finding } from '../../core/finding.js';

const REMEDIATION = 'Harden the Electron window. Do not enable Node integration for remote content.';

const PREFS: Array<{ key: string; bad: string }> = [
  { key: 'nodeIntegration', bad: 'true' },
  { key: 'contextIsolation', bad: 'false' },
  { key: 'sandbox', bad: 'false' },
  { key: 'webSecurity', bad: 'false' },
  { key: 'allowRunningInsecureContent', bad: 'true' },
];

export function lockUsesElectron(source: string): boolean {
  return /"node_modules\/electron"\s*:/.test(source) || /(^|\n)\s*electron@/m.test(source);
}

export function packageUsesElectron(source: string): boolean {
  try {
    const pkg = JSON.parse(source) as {
      dependencies?: Record<string, unknown>;
      devDependencies?: Record<string, unknown>;
      optionalDependencies?: Record<string, unknown>;
    };
    return ['dependencies', 'devDependencies', 'optionalDependencies'].some((key) => {
      const block = pkg[key as 'dependencies'];
      return block !== undefined && Object.prototype.hasOwnProperty.call(block, 'electron');
    });
  } catch {
    return false;
  }
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (source[i] === '\n') {line += 1;}
  }
  return line;
}

function finding(ruleId: string, title: string, severity: Finding['severity'], file: string, line: number, message: string): Finding {
  return {
    id: makeFindingId(ruleId, file, `${line}|${title}`),
    ruleId,
    module: 'config',
    title,
    severity,
    confidence: 'high',
    file,
    line,
    message,
    remediation: REMEDIATION,
  };
}

/** One finding per unsafe webPreferences option, plus openExternal and remote windows. */
export function scanElectronSource(file: string, source: string): Finding[] {
  const out: Finding[] = [];
  const prefs = /webPreferences\s*:\s*\{([^}]*)\}/.exec(source);
  if (prefs?.[1] !== undefined && prefs.index !== undefined) {
    const block = prefs[1];
    const base = prefs.index;
    for (const pref of PREFS) {
      const hit = new RegExp(`\\b${pref.key}\\s*:\\s*${pref.bad}\\b`).exec(block);
      if (hit === null || hit.index === undefined) {continue;}
      out.push(
        finding(
          'CONFIG-ELECTRON-001',
          'Unsafe Electron webPreferences',
          'high',
          file,
          lineOf(source, base + hit.index),
          `webPreferences sets ${pref.key}: ${pref.bad}.`,
        ),
      );
    }
  }
  const external = /shell\.openExternal\s*\(\s*([^)\n]+)\s*\)/.exec(source);
  if (external?.[1] !== undefined && external.index !== undefined) {
    const arg = external[1].trim();
    const literal = /^['"`]/.test(arg);
    const checked = /https:/.test(source);
    if (!literal && !checked) {
      out.push(
        finding(
          'CONFIG-ELECTRON-002',
          'shell.openExternal without an https scheme check',
          'high',
          file,
          lineOf(source, external.index),
          'shell.openExternal is called with a non-literal URL and no https: scheme check.',
        ),
      );
    }
  }
  const remote = /loadURL\s*\(\s*['"]https?:/.test(source);
  if (remote && !source.includes('setWindowOpenHandler') && !source.includes('will-navigate')) {
    const at = source.indexOf('loadURL');
    out.push(
      finding(
        'CONFIG-ELECTRON-003',
        'BrowserWindow loads a remote URL without navigation guards',
        'medium',
        file,
        lineOf(source, at < 0 ? 0 : at),
        'A BrowserWindow loads a remote URL and the file has no setWindowOpenHandler or will-navigate guard.',
      ),
    );
  }
  return out;
}
