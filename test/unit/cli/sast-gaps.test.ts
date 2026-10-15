import { describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

describe('scan --experimental-sast-gaps', () => {
  it('is registered on the scan command', () => {
    const program = createProgram();
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan).toBeDefined();
    expect(scan!.options.map((o) => o.long)).toContain('--experimental-sast-gaps');
  });
});
