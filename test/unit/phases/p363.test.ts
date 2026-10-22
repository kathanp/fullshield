import { describe, expect, it } from 'vitest';

import { enabled, FLAG, MINIFIED_MIN_BYTES, minifiedPackages, type PackageFile } from '../../../src/phases/p363.js';

function file(path: string, text: string): PackageFile {
  return { path, text, bytes: Buffer.byteLength(text) };
}

function huge(newlines: boolean): string {
  const body = 'a'.repeat(MINIFIED_MIN_BYTES + 8);
  return newlines ? body.replace(/a{80}/g, (chunk) => `${chunk}\n`) : body;
}

describe('phase 363 minified files', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(minifiedPackages('pkg', [file('dist/app.js', huge(false))])).toEqual([]);
  });

  it('reports one info row with a count and does not say malicious', () => {
    process.env[FLAG] = '1';
    const findings = minifiedPackages('pkg', [
      file('dist/app.js', huge(false)),
      file('dist/other.js', huge(false)),
      file('src/index.js', 'module.exports = 1;\n'),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.count).toBe(2);
    expect(findings[0]?.message.toLowerCase()).not.toContain('malicious');
    expect(findings[0]?.message).toContain('could not be reviewed as source');
  });

  it('emits nothing for a package of small files', () => {
    process.env[FLAG] = '1';
    expect(minifiedPackages('pkg', [file('index.js', 'module.exports = 1;\n')])).toEqual([]);
  });

  it('emits nothing for a file that has a sibling map', () => {
    process.env[FLAG] = '1';
    const js = file('dist/app.js', huge(false));
    expect(minifiedPackages('pkg', [js, file('dist/app.js.map', '{}')])).toEqual([]);
  });

  it('ignores the package test directory', () => {
    process.env[FLAG] = '1';
    expect(minifiedPackages('pkg', [file('test/app.js', huge(false))])).toEqual([]);
  });
});
