import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runDoctor } from '../../../src/cli/commands/doctor.js';
import { runInit } from '../../../src/cli/commands/init.js';
import { ConfigError, loadConfig } from '../../../src/core/config.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-profile-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('FULLSHIELD_EXPERIMENTAL_')) {
      delete process.env[key];
    }
  }
});

describe('Phase 553 recommended profiles', () => {
  it('accepts the four profile names and rejects unknown', async () => {
    for (const profile of ['recommended', 'ci-strict', 'pr-fast', 'prod-monitor'] as const) {
      await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ profile }), 'utf8');
      const cfg = await loadConfig(dir);
      expect(cfg.profile).toBe(profile);
    }
    await writeFile(join(dir, 'fullshield.config.json'), '{"profile":"enterprise"}\n', 'utf8');
    await expect(loadConfig(dir)).rejects.toBeInstanceOf(ConfigError);
  });

  it('init --recommended writes profile recommended', async () => {
    const result = await runInit({ cwd: dir, recommended: true });
    expect(result.written).toEqual(expect.arrayContaining(['fullshield.config.json']));
    const cfg = JSON.parse(
      await (await import('node:fs/promises')).readFile(join(dir, 'fullshield.config.json'), 'utf8'),
    ) as { profile: string };
    expect(cfg.profile).toBe('recommended');
  });

  it('doctor warns when many experimental flags are set without a profile', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_SAST_GAPS = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_FRAMEWORKS = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_CLASSES = '1';
    await writeFile(join(dir, 'fullshield.config.json'), '{"failOn":"high"}\n', 'utf8');
    const text = await runDoctor(dir, { offline: true });
    expect(text).toMatch(/profile/i);
    expect(text).toMatch(/experimental/i);
  });

  it('default config without profile still loads', async () => {
    const cfg = await loadConfig(dir);
    expect(cfg.profile).toBeUndefined();
    expect(cfg.failOn).toBe('high');
  });
});
