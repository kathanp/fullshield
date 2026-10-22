/**
 * Phase 363. Source-less package files.
 * Off unless FULLSHIELD_EXPERIMENTAL_MINIFIED=1.
 * Constants sit beside the committed entropy floor and are not tuned per repo.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MINIFIED';

/** Matches the committed secret-entropy floor. Not tuned per repository. */
export const ENTROPY_FLOOR = 4.5;
export const MINIFIED_MIN_BYTES = 50 * 1024;
export const MINIFIED_MAX_NEWLINE_RATIO = 0.02;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PackageFile {
  path: string;
  bytes: number;
  text: string;
}

export interface MinifiedFinding {
  ruleId: 'DEPS-MINIFIED-001';
  severity: 'info';
  packageName: string;
  count: number;
  message: string;
}

function newlineRatio(text: string, bytes: number): number {
  if (bytes === 0) {
    return 1;
  }
  let newlines = 0;
  for (const char of text) {
    if (char === '\n') {
      newlines += 1;
    }
  }
  return newlines / bytes;
}

function isTestPath(filePath: string): boolean {
  const parts = filePath.split(/[/\\]/);
  return parts.includes('test') || parts.includes('__tests__');
}

function hasMap(file: PackageFile, files: readonly PackageFile[]): boolean {
  const mapPath = `${file.path}.map`;
  return files.some((other) => other.path === mapPath);
}

export function minifiedPackages(packageName: string, files: readonly PackageFile[]): MinifiedFinding[] {
  if (!enabled()) {
    return [];
  }
  let count = 0;
  for (const file of files) {
    if (!file.path.endsWith('.js')) {
      continue;
    }
    if (isTestPath(file.path)) {
      continue;
    }
    if (file.bytes <= MINIFIED_MIN_BYTES) {
      continue;
    }
    if (newlineRatio(file.text, file.bytes) >= MINIFIED_MAX_NEWLINE_RATIO) {
      continue;
    }
    if (hasMap(file, files)) {
      continue;
    }
    count += 1;
  }
  if (count === 0) {
    return [];
  }
  return [
    {
      ruleId: 'DEPS-MINIFIED-001',
      severity: 'info',
      packageName,
      count,
      message: `${count} file(s) could not be reviewed as source.`,
    },
  ];
}
