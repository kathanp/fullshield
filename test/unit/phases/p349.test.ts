import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p349.js';


afterEach(() => {
  delete process.env[phase.FLAG];
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
});
