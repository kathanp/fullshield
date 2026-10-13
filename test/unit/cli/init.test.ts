import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runInit } from '../../../src/cli/commands/init.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-init-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function assertGithubWorkflow(yaml: string): void {
  expect(yaml).not.toMatch(/^\t/m);
  expect(yaml).toContain('name:');
  expect(yaml).toContain('on:');
  expect(yaml).toContain('jobs:');
  expect(yaml).toContain('pull_request');
  expect(yaml).toContain('fullshield scan');
  expect(yaml).toContain('--sarif');
  expect(yaml).toContain('--fail-on high');
  expect(yaml).toContain('upload-sarif');
}

describe('fullshield init', () => {
  it('writes a valid GitHub workflow, config, hook, and GitLab snippet', async () => {
    const result = await runInit({ cwd: dir });
    expect(result.written).toEqual(
      expect.arrayContaining([
        'fullshield.config.json',
        '.github/workflows/fullshield.yml',
        '.gitlab-ci.yml',
        '.fullshield/pre-commit.sh',
      ]),
    );
    const workflow = await readFile(join(dir, '.github/workflows/fullshield.yml'), 'utf8');
    assertGithubWorkflow(workflow);
    const config = JSON.parse(await readFile(join(dir, 'fullshield.config.json'), 'utf8')) as {
      failOn: string;
    };
    expect(config.failOn).toBe('high');
    const hook = await readFile(join(dir, '.fullshield/pre-commit.sh'), 'utf8');
    expect(hook).toContain('--modules secrets');
    expect(hook).toContain('--staged');
  });

  it('does not overwrite existing files without --force', async () => {
    await runInit({ cwd: dir });
    const again = await runInit({ cwd: dir });
    expect(again.written).toEqual([]);
  });
});
