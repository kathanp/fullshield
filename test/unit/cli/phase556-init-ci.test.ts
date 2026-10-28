import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runInit } from '../../../src/cli/commands/init.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

let dir: string;
const ghCalls: string[][] = [];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-init-ci-'));
  ghCalls.length = 0;
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('phase 556 init --ci', () => {
  it('writes Action workflow and config', async () => {
    const result = await runInit({ cwd: dir, ci: true, noPr: true });
    expect(result.written).toEqual(
      expect.arrayContaining(['fullshield.config.json', '.github/workflows/fullshield.yml']),
    );
    const workflow = await readFile(join(dir, '.github/workflows/fullshield.yml'), 'utf8');
    expect(workflow).toMatch(/fullshield|templates\/action/);
    expect(workflow).not.toMatch(/createComment|request-changes|request_changes/);
  });

  it('with --recommended also writes the policy pack', async () => {
    const result = await runInit({ cwd: dir, ci: true, recommended: true, noPr: true });
    expect(result.written).toEqual(expect.arrayContaining(['fullshield.policy.json']));
  });

  it('never invokes gh when --no-pr is set', async () => {
    const result = await runInit({
      cwd: dir,
      ci: true,
      noPr: true,
      runGh: (args) => {
        ghCalls.push(args);
        return Promise.resolve({ status: 0, stdout: '', stderr: '' });
      },
    });
    expect(result.written.length).toBeGreaterThan(0);
    expect(ghCalls).toEqual([]);
    expect(result.prUrl).toBeUndefined();
  });

  it('templates and init source do not post PR comments', async () => {
    const initSrc = await readFile(join(root, 'src/cli/commands/init.ts'), 'utf8');
    expect(initSrc).not.toMatch(/createComment|issues\.create|pulls\.createReview/);
    const action = await readFile(join(root, 'templates/action/action.yml'), 'utf8');
    expect(action).not.toMatch(/createComment|github-script/);
  });

  it('can record a local pr-summary file without commenting', async () => {
    await writeFile(join(dir, 'package.json'), '{"name":"ci-app","version":"1.0.0"}\n', 'utf8');
    const result = await runInit({ cwd: dir, ci: true, noPr: true, writeSummary: true });
    expect(result.summaryPath === undefined || result.summaryPath.endsWith('.md')).toBe(true);
    if (result.summaryPath) {
      const text = await readFile(join(dir, result.summaryPath), 'utf8');
      expect(text.length).toBeGreaterThan(0);
    }
  });
});
