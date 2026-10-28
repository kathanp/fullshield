import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runDoctor } from '../../../src/cli/commands/doctor.js';
import { runInit } from '../../../src/cli/commands/init.js';
import { loadPolicy } from '../../../src/policy/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const packTemplate = join(root, 'templates', 'policy', 'fullshield.policy.json');

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-policy-pack-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  delete process.env.FULLSHIELD_EXPERIMENTAL_POLICY;
});

describe('phase 555 policy pack', () => {
  it('ships a starter policy with failOn main, secrets required, and exception shape', async () => {
    const raw = JSON.parse(await readFile(packTemplate, 'utf8')) as {
      requiredModules?: string[];
      failOn?: Record<string, string>;
      exceptions?: unknown[];
    };
    expect(raw.failOn?.main).toBe('critical');
    expect(raw.requiredModules).toEqual(expect.arrayContaining(['secrets']));
    expect(Array.isArray(raw.exceptions)).toBe(true);
  });

  it('loads policy when profile is recommended without the experimental flag', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_POLICY;
    const pack = await readFile(packTemplate, 'utf8');
    await writeFile(join(dir, 'fullshield.policy.json'), pack, 'utf8');
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ profile: 'recommended', failOn: 'high' }),
      'utf8',
    );
    const policy = await loadPolicy(dir, { profile: 'recommended' });
    expect(policy).toBeDefined();
    expect(policy?.failOn?.main).toBe('critical');
    expect(policy?.requiredModules).toEqual(expect.arrayContaining(['secrets']));
  });

  it('does not load policy without profile or experimental flag', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_POLICY;
    const pack = await readFile(packTemplate, 'utf8');
    await writeFile(join(dir, 'fullshield.policy.json'), pack, 'utf8');
    await writeFile(join(dir, 'fullshield.config.json'), '{"failOn":"high"}\n', 'utf8');
    const policy = await loadPolicy(dir, {});
    expect(policy).toBeUndefined();
  });

  it('init --recommended writes the policy pack', async () => {
    const result = await runInit({ cwd: dir, recommended: true });
    expect(result.written).toEqual(expect.arrayContaining(['fullshield.policy.json']));
    const written = JSON.parse(await readFile(join(dir, 'fullshield.policy.json'), 'utf8')) as {
      failOn?: { main?: string };
    };
    expect(written.failOn?.main).toBe('critical');
  });

  it('doctor warns when profile is set but policy file is missing', async () => {
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ profile: 'recommended', failOn: 'high' }),
      'utf8',
    );
    const text = await runDoctor(dir, { offline: true });
    expect(text).toMatch(/policy/i);
    expect(text).toMatch(/missing|absent/i);
  });
});
