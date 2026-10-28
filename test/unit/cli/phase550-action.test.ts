import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const actionDir = join(root, 'templates', 'action');
const actionYml = join(actionDir, 'action.yml');
const workflowViaAction = join(root, 'templates', 'github-workflow-action.yml');

const FORBIDDEN = [
  /github\.rest\.issues\.createComment/,
  /octokit\.rest\.pulls\.createReview/,
  /actions\/github-script/,
  /https?:\/\/(?!api\.osv\.dev|registry\.npmjs\.org|github\.com|objects\.githubusercontent\.com)[^\s"']+/i,
];

function assertNoPrBot(yaml: string): void {
  expect(yaml).not.toMatch(/createComment|addComments|request-changes|request_changes/);
  expect(yaml).not.toMatch(/telemetry\.|phone-home|collector\./i);
  for (const re of FORBIDDEN) {
    expect(yaml).not.toMatch(re);
  }
}

describe('Phase 550 GitHub Action template', () => {
  it('ships a composite Action with SARIF upload, baseline cache, and a pinned fullshield version', async () => {
    const yaml = await readFile(actionYml, 'utf8');
    expect(yaml).not.toMatch(/^\t/m);
    expect(yaml).toMatch(/runs:\s*\n\s*using:\s*['"]?composite['"]?/m);
    expect(yaml).toMatch(/upload-sarif|codeql-action\/upload-sarif/);
    expect(yaml).toMatch(/actions\/cache@|cache:/);
    expect(yaml).toMatch(/fullshield@\d+\.\d+\.\d+/);
    expect(yaml).toContain('baseline');
    assertNoPrBot(yaml);
  });

  it('ships an init workflow that uses the Action and does not post PR comments', async () => {
    const yaml = await readFile(workflowViaAction, 'utf8');
    expect(yaml).not.toMatch(/^\t/m);
    expect(yaml).toContain('name:');
    expect(yaml).toContain('on:');
    expect(yaml).toContain('jobs:');
    expect(yaml).toMatch(/uses:\s*.*templates\/action|uses:\s*.*fullshield-action/);
    expect(yaml).toMatch(/upload-sarif|codeql-action\/upload-sarif|fullshield-action|templates\/action/);
    assertNoPrBot(yaml);
  });
});
