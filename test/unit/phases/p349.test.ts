import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p349.js';


const UNPUBLISHED = 'FULLSHIELD_EXPERIMENTAL_NPM_REG_UNPUBLISHED';

afterEach(() => {
  delete process.env[phase.FLAG];
  delete process.env[UNPUBLISHED];
});

const input = {
  packageName: 'left',
  parent: 'app',
  parentRange: '^1.0.0',
  locked: '1.0.0',
  versions: [{ version: '1.0.0' }, { version: '1.0.1' }],
  ranges: [{ introduced: '0.0.0', fixed: '1.0.1' }],
};

describe('phase 349', () => {
  it('proposes nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.proposeUpgrade(input)).toBeUndefined();
  });

  it('proposes a version inside the parent range', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.proposeUpgrade(input)?.version).toBe('1.0.1');
    expect(phase.proposeUpgrade({ ...input, parentRange: '^2.0.0', locked: '2.0.0' })?.kind).toBe('nested-override');
    expect(phase.proposeUpgrade({ ...input, versions: [] })).toBeUndefined();
  });

  it('proposes nothing when every cached version stays vulnerable', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.proposeUpgrade({ ...input, ranges: [{ introduced: '0.0.0' }] })).toBeUndefined();
    expect(phase.proposeUpgrade({ ...input, ranges: [] })?.kind).toBe('bump');
    expect(phase.proposeUpgrade({ ...input, ranges: [{ fixed: '1.0.1' }] })?.version).toBe('1.0.1');
  });

  it('names an unpublished cached version only when that state is not hidden', () => {
    process.env[phase.FLAG] = '1';
    const versions = [{ version: '1.0.1', unpublished: true }, { version: '2.0.0' }];
    const open = phase.proposeUpgrade({ ...input, versions });
    expect(open).toMatchObject({ kind: 'bump', version: '1.0.1', witness: 'unpublished state was not computed' });
    process.env[UNPUBLISHED] = '1';
    expect(phase.proposeUpgrade({ ...input, versions })?.kind).toBe('nested-override');
    delete process.env[UNPUBLISHED];
  });
});
