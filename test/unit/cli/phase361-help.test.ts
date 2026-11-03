import { describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

describe('3.6.1 experimental help', () => {
  it('cuts experimental flag names in scan --help by at least 30%', () => {
    const scan = createProgram().commands.find((command) => command.name() === 'scan');
    expect(scan).toBeDefined();
    const registered = scan!.options.filter((option) => (option.long ?? '').startsWith('--experimental-'));
    const help = scan!.helpInformation();
    const shown = new Set([...help.matchAll(/--experimental-[a-z0-9-]+/g)].map((match) => match[0]));
    expect(registered.length).toBeGreaterThan(10);
    expect(shown.size).toBeLessThanOrEqual(Math.floor(registered.length * 0.7));
    expect(registered.length - shown.size).toBeGreaterThanOrEqual(Math.ceil(registered.length * 0.3));
    const hidden = registered.find((option) => option.hidden);
    expect(hidden?.long).toBeDefined();
    expect(help).not.toContain(hidden!.long!);
    expect(help).toContain('--experimental-budget');
  });
});
