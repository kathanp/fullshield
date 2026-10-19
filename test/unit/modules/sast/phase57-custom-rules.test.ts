import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { formatCliError } from '../../../../src/cli/errors.js';

const app = join(import.meta.dirname, '../../../fixtures/custom-rules-app');

describe('phase 57 custom rules', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('reports the fixture sink and stays quiet on a literal', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES = '1';
    const result = await scan({ cwd: app, modules: ['sast'], offline: true });
    const hits = result.findings.filter((finding) => finding.ruleId === 'CUSTOM-SINK-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.snippet).toContain('req.body');
  });

  it('does not load the rules file when the flag is off, and an invalid file fails closed', async () => {
    const off = await scan({ cwd: app, modules: ['sast'], offline: true });
    expect(off.findings.some((finding) => finding.ruleId === 'CUSTOM-SINK-001')).toBe(false);

    const dir = await mkdtemp(join(tmpdir(), 'fs-custom-rules-'));
    dirs.push(dir);
    await mkdir(join(dir, 'src'));
    await writeFile(join(dir, 'src', 'index.js'), 'danger(req.body)\n');
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ modules: ['sast'], sast: { customRules: 'rules.json' } }),
    );
    await writeFile(join(dir, 'rules.json'), '{"rules":[{"id":"X","eval":"process.exit(1)"}]}\n');
    process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES = '1';
    await expect(scan({ cwd: dir, modules: ['sast'], offline: true })).rejects.toThrow(/custom rules/);
    expect(formatCliError(new Error('custom rules file must be a JSON object'))).toContain('FS-E010');
  });
});
