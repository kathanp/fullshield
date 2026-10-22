import { describe, expect, it } from 'vitest';

import { enabled, FLAG, manifestMismatches, type ManifestCompareInput } from '../../../src/phases/p361.js';

function input(over: Partial<ManifestCompareInput> = {}): ManifestCompareInput {
  return {
    packageName: 'left-pad',
    lock: { name: 'left-pad', version: '1.0.0', scripts: { install: 'node build.js' }, dependencies: { ms: '1.0.0' } },
    packument: { name: 'left-pad', version: '1.0.0', scripts: { install: 'node build.js' }, dependencies: { ms: '1.0.0' } },
    tarball: { name: 'left-pad', version: '1.0.0', scripts: { install: 'node build.js' }, dependencies: { ms: '1.0.0' } },
    phase169ReportedNameOrVersion: false,
    ...over,
  };
}

describe('phase 361 manifest mismatch', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(manifestMismatches(input({ tarball: { scripts: { install: 'curl example.invalid' } } }))).toEqual([]);
  });

  it('reports a tarball install script absent from the packument', () => {
    process.env[FLAG] = '1';
    const findings = manifestMismatches(
      input({
        packument: { scripts: {} },
        tarball: { scripts: { install: 'node-gyp rebuild' } },
        lock: {},
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.field).toBe('scripts.install');
    expect(findings[0]?.message).toContain('node-gyp rebuild');
  });

  it('emits nothing when scripts match', () => {
    process.env[FLAG] = '1';
    expect(manifestMismatches(input())).toEqual([]);
  });

  it('emits this id for a name mismatch only when phase 169 is off', () => {
    process.env[FLAG] = '1';
    const mismatched = input({
      lock: { name: 'left-pad' },
      packument: { name: 'left-pad' },
      tarball: { name: 'other-name' },
    });
    const when169On = manifestMismatches({ ...mismatched, phase169ReportedNameOrVersion: true });
    expect(when169On.map((row) => row.ruleId)).not.toContain('DEPS-MANIFEST-MISMATCH-001');
    const when169Off = manifestMismatches({ ...mismatched, phase169ReportedNameOrVersion: false });
    expect(when169Off.map((row) => row.field)).toContain('name');
    expect(when169Off[0]?.severity).toBe('high');
  });

  it('does not report a dependency range that canonicalizes', () => {
    process.env[FLAG] = '1';
    const findings = manifestMismatches(
      input({
        lock: { dependencies: { ms: '1.0' } },
        packument: { dependencies: { ms: '1.0.0' } },
        tarball: { dependencies: { ms: '1.0.0' } },
      }),
    );
    expect(findings).toEqual([]);
  });
});
