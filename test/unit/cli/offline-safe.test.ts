import { describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

describe('scan --offline-safe', () => {
  it('is registered as an alias of --offline on the scan command', () => {
    const program = createProgram();
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan).toBeDefined();
    const names = scan!.options.map((o) => o.long);
    expect(names).toContain('--offline');
    expect(names).toContain('--offline-safe');
  });
});
