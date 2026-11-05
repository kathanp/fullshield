import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import { scriptReachContext } from '../../../../src/modules/deps/script-context.js';

import { makeFindingId, type Finding } from '../../../../src/core/finding.js';
import { applyReachability } from '../../../../src/modules/deps/reachability.js';

function vuln(name: string): Finding {
  return {
    id: makeFindingId('DEPS-VULN-001', 'package.json', `${name}@1.0.0|GHSA-1`),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: 'Vulnerable dependency',
    severity: 'high',
    confidence: 'high',
    file: 'package.json',
    snippet: `${name}@1.0.0`,
    message: `${name}@1.0.0 is affected by GHSA-1.`,
    remediation: 'upgrade',
  };
}

function graphFor(name: string) {
  return {
    packages: [],
    edges: new Map<string, Set<string>>(),
    directProd: new Set<string>([name]),
    directDev: new Set<string>(),
    edgesKnown: true,
  };
}

describe('3.7.0 script and bin reach', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_NPM_REACH_BIN;
  });

  it('marks a script-only dependency without the experimental flag', () => {
    const next = applyReachability([vuln('mocha')], {
      productionUsage: new Map(),
      graph: graphFor('mocha'),
      scripts: { test: 'mocha --timeout 1000' },
      bins: new Map([['mocha', { mocha: 'bin/mocha.js' }]]),
    });
    expect(next[0]?.reachability).toBe('reachable-via-script');
    expect(next[0]?.reachability).not.toBe('not-imported');
    expect(next[0]?.severity).toBe('high');
  });

  it('marks a package whose bin is the script command when the flag is on', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_REACH_BIN = '1';
    const next = applyReachability([vuln('mocha')], {
      productionUsage: new Map(),
      graph: graphFor('mocha'),
      scripts: { test: 'mocha --timeout 1000' },
      bins: new Map([['mocha', { mocha: 'bin/mocha.js' }]]),
    });
    expect(next[0]?.reachability).toBe('reachable-via-script');
    expect(next[0]?.severity).toBe('high');
  });

  it('still marks a script-only dependency when the experimental flag is off', () => {
    const next = applyReachability([vuln('mocha')], {
      productionUsage: new Map(),
      graph: graphFor('mocha'),
      scripts: { test: 'mocha' },
      bins: new Map([['mocha', { mocha: 'bin/mocha.js' }]]),
    });
    expect(next[0]?.reachability).toBe('reachable-via-script');
    expect(next[0]?.severity).toBe('high');
  });

  it('does not treat NodeGoat start or the goof test script as those packages', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_REACH_BIN = '1';
    const forever = applyReachability([vuln('forever')], {
      productionUsage: new Map(),
      graph: graphFor('forever'),
      scripts: { start: 'node server.js' },
      bins: new Map([['forever', { forever: 'bin/forever' }]]),
    });
    const tap = applyReachability([vuln('tap')], {
      productionUsage: new Map(),
      graph: graphFor('tap'),
      scripts: { test: 'snyk test' },
      bins: new Map([['tap', { tap: 'bin/tap.js' }]]),
    });
    expect(forever[0]?.reachability).toBe('not-imported');
    expect(tap[0]?.reachability).toBe('not-imported');
  });

  it('reads root scripts and an installed bin without the experimental flag', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'fs-script-'));
    writeFileSync(join(cwd, 'package.json'), JSON.stringify({ scripts: { test: 'mocha' } }));
    const binDir = join(cwd, 'node_modules', 'mocha');
    mkdirSync(binDir, { recursive: true });
    writeFileSync(join(binDir, 'package.json'), JSON.stringify({ bin: { mocha: 'bin/mocha.js' } }));
    const graph = graphFor('mocha');
    const loaded = await scriptReachContext(cwd, graph);
    expect(loaded.scripts).toEqual({ test: 'mocha' });
    expect(loaded.bins?.get('mocha')).toEqual({ mocha: 'bin/mocha.js' });
    writeFileSync(join(cwd, 'package.json'), JSON.stringify({ scripts: { test: 1, start: 'node server.js' } }));
    writeFileSync(join(binDir, 'package.json'), JSON.stringify({ bin: './bin/mocha.js' }));
    const stringBin = await scriptReachContext(cwd, graph);
    expect(stringBin.scripts).toEqual({ start: 'node server.js' });
    expect(stringBin.bins?.get('mocha')).toBe('./bin/mocha.js');
    writeFileSync(join(binDir, 'package.json'), JSON.stringify({ bin: [] }));
    expect((await scriptReachContext(cwd, graph)).bins?.has('mocha')).toBe(false);
    writeFileSync(join(binDir, 'package.json'), 'not-json');
    expect((await scriptReachContext(cwd, graph)).bins?.has('mocha')).toBe(false);
    const missing = await scriptReachContext(join(cwd, 'absent'), graph);
    expect(missing.scripts).toBeUndefined();
    expect(missing.bins?.size).toBe(0);
  });
});
