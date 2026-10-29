import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { formatCliError } from '../../../src/cli/errors.js';
import { loadConfig } from '../../../src/core/config.js';
import type { Finding } from '../../../src/core/finding.js';
import { enrichEpss, epssPriority, parseEpssTable, readEpssTable } from '../../../src/modules/deps/epss-local.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function finding(partial: Partial<Finding>): Finding {
  return {
    id: 'id-1',
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: 'Vulnerable dependency',
    severity: 'high',
    confidence: 'high',
    file: 'package-lock.json',
    message: 'affected',
    remediation: 'bump',
    references: ['GHSA-1'],
    ...partial,
  };
}

describe('phase 560 local EPSS', () => {
  it('accepts 0 and 1 and rejects scores outside that range', () => {
    expect(parseEpssTable(JSON.stringify({ 'GHSA-1': { epss: 0, kev: false } }))['GHSA-1']).toEqual({ epss: 0, kev: false });
    expect(parseEpssTable(JSON.stringify({ 'GHSA-1': { epss: 1, kev: true } }))['GHSA-1']).toEqual({ epss: 1, kev: true });
    expect(() => parseEpssTable(JSON.stringify({ 'GHSA-1': { epss: -0.001, kev: false } }))).toThrow(/FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL/);
    expect(() => parseEpssTable(JSON.stringify({ 'GHSA-1': { epss: 1.001, kev: false } }))).toThrow(/epss must be from 0 to 1/);
    expect(() => parseEpssTable('not-json')).toThrow(/not JSON/);
    expect(() => parseEpssTable('[]')).toThrow(/must be an object/);
    expect(() => parseEpssTable(JSON.stringify({ 'GHSA-1': 1 }))).toThrow(/epss must be from 0 to 1/);
    expect(() => parseEpssTable(JSON.stringify({ 'GHSA-1': { epss: 0.2, kev: 'yes' } }))).toThrow(/kev must be a boolean/);
    expect(formatCliError(new Error('epss must be from 0 to 1 (FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL)'))).toMatch(/FS-E023/);
  });

  it('sets epssPriority without changing severity and leaves unmatched rows alone', () => {
    const row = finding({ severity: 'critical', reachability: 'reachable' });
    const [enriched, untouched] = enrichEpss(
      [row, finding({ id: 'id-2', references: ['OTHER'] })],
      { 'GHSA-1': { epss: 0.5, kev: true } },
    );
    expect(enriched?.severity).toBe('critical');
    expect(enriched?.ruleId).toBe('DEPS-VULN-001');
    expect(enriched?.epss).toBe(0.5);
    expect(enriched?.kev).toBe(true);
    expect(enriched?.epssPriority).toBe(epssPriority({ epss: 0.5, kev: true, reachability: 'reachable', severity: 'critical' }));
    expect(enriched?.epssPriority).toBe(1000 + 50 + 10 + 4);
    expect(untouched?.epss).toBeUndefined();
    const again = enrichEpss([row], { 'GHSA-1': { epss: 0.5, kev: true } });
    expect(JSON.stringify(again)).toBe(JSON.stringify(enrichEpss([row], { 'GHSA-1': { epss: 0.5, kev: true } })));
    expect(epssPriority({ epss: 0, kev: false, severity: 'info' })).toBe(0);
  });

  it('does not read deps.epssFile when the flag is off', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-epss-'));
    dirs.push(dir);
    await writeFile(join(dir, 'epss.json'), JSON.stringify({ 'GHSA-1': { epss: 0.2, kev: false } }), 'utf8');
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ deps: { epssFile: 'epss.json', offline: true } }), 'utf8');
    const off = await loadConfig(dir);
    expect(off.deps.epssFile).toBeUndefined();
    process.env.FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL = '1';
    const on = await loadConfig(dir);
    expect(on.deps.epssFile).toBe('epss.json');
    await expect(readEpssTable(dir, 'missing.json')).rejects.toThrow(/FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL/);
    await expect(readEpssTable(dir, 'epss.json')).resolves.toMatchObject({ 'GHSA-1': { epss: 0.2, kev: false } });
  });
});
