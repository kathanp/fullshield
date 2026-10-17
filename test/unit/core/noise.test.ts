import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { makeFindingId, type Finding } from '../../../src/core/finding.js';
import { scan } from '../../../src/core/engine.js';
import { dedupeSastSinks } from '../../../src/modules/sast/engine.js';
import { groupPackageAdvisories } from '../../../src/modules/deps/reachability.js';

let dir: string;

afterEach(async () => {
  if (dir !== undefined) await rm(dir, { recursive: true, force: true });
});

function vuln(version: string, advisory: string): Finding {
  const snippet = `lodash@${version}`;
  return {
    id: makeFindingId('DEPS-VULN-001', 'package-lock.json', `${snippet}|${advisory}`),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: `Vulnerable dependency ${snippet}`,
    severity: version === '4.17.20' ? 'high' : 'medium',
    confidence: 'high',
    file: 'package-lock.json',
    snippet,
    message: `${snippet} is affected by ${advisory}.`,
    remediation: 'Upgrade.',
    references: [advisory],
    dependencyPath: version === '4.17.20' ? ['express', 'lodash'] : ['mocha', 'lodash'],
  };
}

describe('dependency advisory grouping', () => {
  it('collapses the same package and advisory across versions and keeps every path', () => {
    const grouped = groupPackageAdvisories([
      vuln('4.17.11', 'GHSA-1'),
      vuln('4.17.20', 'GHSA-1'),
      vuln('4.17.11', 'GHSA-2'),
    ]);
    const first = grouped.filter((f) => f.references?.[0] === 'GHSA-1');
    expect(first).toHaveLength(1);
    expect(first[0]?.severity).toBe('high');
    expect(first[0]?.snippet).toContain('4.17.11');
    expect(first[0]?.snippet).toContain('4.17.20');
    expect(first[0]?.dependencyPaths?.map((p) => p.join('>')).sort()).toEqual([
      'express>lodash',
      'mocha>lodash',
    ]);
    expect(first[0]?.message).toContain('Versions:');
    expect(grouped.filter((f) => f.references?.[0] === 'GHSA-2')).toHaveLength(1);
  });
});

describe('SAST sink dedupe', () => {
  it('keeps one finding per ruleId and sink line', () => {
    const base: Finding = {
      id: 'a',
      ruleId: 'SAST-SQLI-001',
      module: 'sast',
      title: 'SQL injection',
      severity: 'high',
      confidence: 'high',
      file: 'db.js',
      line: 10,
      message: 'first',
      remediation: 'parameterize',
    };
    const out = dedupeSastSinks([
      base,
      { ...base, id: 'b', message: 'second', column: 4 },
      { ...base, id: 'c', line: 11 },
    ]);
    expect(out.map((f) => f.id)).toEqual(['a', 'c']);
  });
});

describe('SAST file size skip', () => {
  it('reports an info finding and does not parse a file over the cap', async () => {
    dir = await mkdtemp(join(tmpdir(), 'fullshield-skip-'));
    await mkdir(join(dir, 'src'), { recursive: true });
    const source = `${' '.repeat(80)}\nconst { exec } = require('child_process');\nfunction go(req){ exec(req.query.cmd); }\n`;
    await writeFile(join(dir, 'src', 'big.js'), source);
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ modules: ['sast'], sast: { maxFileBytes: 40 } }),
    );
    const result = await scan({ cwd: dir, modules: ['sast'] });
    expect(result.findings.some((f) => f.ruleId === 'SAST-CMDI-001')).toBe(false);
    const skip = result.findings.find((f) => f.ruleId === 'SAST-SKIP-001');
    expect(skip?.severity).toBe('info');
    expect(skip?.message).toContain('src/big.js');
    expect(skip?.message).toContain('parse limit');
  });
});
