import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ConfigError, DEFAULT_CONFIG, loadConfig } from '../../../src/core/config.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-config-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('loadConfig', () => {
  it('returns defaults when no config file exists', async () => {
    const config = await loadConfig(dir);
    expect(config).toEqual(DEFAULT_CONFIG);
    // Must be a copy, not a shared reference.
    expect(config).not.toBe(DEFAULT_CONFIG);
    expect(config.modules).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(config.failOn).toBe('high');
  });

  it('merges a config file over defaults', async () => {
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ modules: ['secrets'], failOn: 'medium', ignore: ['build/**'] }),
    );
    const config = await loadConfig(dir);
    expect(config.modules).toEqual(['secrets']);
    expect(config.failOn).toBe('medium');
    expect(config.ignore).toEqual(['build/**']);
    // Untouched keys keep defaults.
    expect(config.baseline).toBe(DEFAULT_CONFIG.baseline);
    expect(config.notify).toEqual(DEFAULT_CONFIG.notify);
  });

  it('loads from an explicit config path', async () => {
    const file = join(dir, 'custom.json');
    await writeFile(file, JSON.stringify({ failOn: 'critical' }));
    const config = await loadConfig(dir, file);
    expect(config.failOn).toBe('critical');
  });

  it('throws ConfigError when an explicit config path does not exist', async () => {
    await expect(loadConfig(dir, join(dir, 'missing.json'))).rejects.toThrow(ConfigError);
  });

  it('throws ConfigError on invalid JSON', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), '{ not json');
    await expect(loadConfig(dir)).rejects.toThrow(ConfigError);
  });

  it('throws ConfigError on an unknown module name', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ modules: ['sast', 'nope'] }));
    await expect(loadConfig(dir)).rejects.toThrow(/unknown module "nope"/);
  });

  it('throws ConfigError on an invalid failOn severity', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ failOn: 'severe' }));
    await expect(loadConfig(dir)).rejects.toThrow(/invalid "failOn"/);
  });

  it('throws ConfigError on unknown top-level keys', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ failon: 'high' }));
    await expect(loadConfig(dir)).rejects.toThrow(/unknown key "failon"/);
  });

  it('throws ConfigError when ignore is not an array of strings', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ ignore: [42] }));
    await expect(loadConfig(dir)).rejects.toThrow(/"ignore" must be an array/);
  });

  it('throws ConfigError when notify is malformed', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ notify: { slack: true } }));
    await expect(loadConfig(dir)).rejects.toThrow(/"notify" must be an object/);
  });

  it('merges a deps block over defaults', async () => {
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ deps: { offline: true, cacheDir: 'osv-cache' } }),
    );
    const config = await loadConfig(dir);
    expect(config.deps).toEqual({ offline: true, cacheDir: 'osv-cache' });
  });

  it('throws ConfigError when deps.offline is not a boolean', async () => {
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ deps: { offline: 'yes' } }));
    await expect(loadConfig(dir)).rejects.toThrow(/"deps.offline"/);
  });
});

