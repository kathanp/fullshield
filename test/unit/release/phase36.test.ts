import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../src/modules/sast/engine.js';
import { githubOidcToken } from '../../../scripts/github-oidc.mjs';
import {
  approvedDiffMatches,
  attestationsPresent,
  baselineTag,
  bumpKind,
  bumpSatisfies,
  diffFindingKeys,
  formatSnapshotDiff,
  packBudgetErrors,
  packReportEntry,
  parseLeadingJson,
  requiredBump,
} from '../../../scripts/release-checks.mjs';

describe('Phase 36 release checks', () => {
  it('keeps npm publish as a dry run in CI and does not publish', () => {
    const ci = readFileSync(join(process.cwd(), '.github', 'workflows', 'ci.yml'), 'utf8');
    expect(ci).toContain('npm publish --dry-run');
    expect(ci).not.toContain('npm publish\n');
  });

  it('requires a minor bump when a rule, flag, command, export, or stable scan changes', () => {
    expect(requiredBump({})).toBe('patch');
    expect(requiredBump({ newRuleIds: ['SAST-NEW-001'] })).toBe('minor');
    expect(requiredBump({ newFlags: ['--experimental-taint-v2'] })).toBe('minor');
    expect(requiredBump({ newCommands: ['doctor'] })).toBe('minor');
    expect(requiredBump({ newExports: ['./runtime/koa'] })).toBe('minor');
    expect(requiredBump({ stableChanged: true })).toBe('minor');
  });

  it('skips a tag that points at HEAD and uses the previous release', () => {
    const sha = (tag: string) => (tag === 'v0.2.0' ? 'head' : tag);
    expect(baselineTag(['v0.2.0', 'v0.1.3', 'v0.1.1'], 'head', sha)).toBe('v0.1.3');
    expect(baselineTag(['v0.1.3', 'v0.1.1'], 'other', sha)).toBe('v0.1.3');
    expect(() => baselineTag(['v0.2.0'], 'head', sha)).toThrow(/previous/);
  });

  it('rejects a patch when a minor bump is required and rejects a decrease', () => {
    expect(bumpKind('0.1.3', '0.1.4')).toBe('patch');
    expect(bumpKind('0.1.3', '0.2.0')).toBe('minor');
    expect(bumpKind('0.1.3', '0.1.3')).toBe('none');
    expect(bumpKind('0.1.3', '0.1.2')).toBe('decrease');
    expect(bumpSatisfies('minor', 'minor')).toBe(true);
    expect(bumpSatisfies('patch', 'minor')).toBe(false);
    expect(bumpSatisfies('none', 'patch')).toBe(false);
    expect(bumpSatisfies('decrease', 'patch')).toBe(false);
  });

  it('reads an npm 11 array and an npm 12 object from pack output', () => {
    const npm11 = 'npm notice\n[{"unpackedSize": 10, "files": [{"path": "a"}]}]\n';
    const npm12 = '{"fullshield": {"unpackedSize": 20, "files": [{"path": "b"}]}}\n';
    expect(packReportEntry(parseLeadingJson(npm11)).unpackedSize).toBe(10);
    expect(packReportEntry(parseLeadingJson(npm12)).files).toHaveLength(1);
  });

  it('fails the pack budget on size, file count, or a new hard dependency', () => {
    const ok = packBudgetErrors({
      unpackedBytes: 1_600_000,
      fileCount: 101,
      hardDeps: ['commander'],
      previousHardDeps: ['commander'],
    });
    expect(ok).toEqual([]);
    expect(
      packBudgetErrors({
        unpackedBytes: 2_100_000,
        fileCount: 101,
        hardDeps: ['commander'],
        previousHardDeps: ['commander'],
      }).join(' '),
    ).toMatch(/unpacked/);
    expect(
      packBudgetErrors({
        unpackedBytes: 100,
        fileCount: 121,
        hardDeps: ['commander'],
        previousHardDeps: ['commander'],
      }).join(' '),
    ).toMatch(/file count/);
    expect(
      packBudgetErrors({
        unpackedBytes: 100,
        fileCount: 10,
        hardDeps: ['commander', 'left-pad'],
        previousHardDeps: ['commander'],
      }),
    ).toEqual(['new hard dependency left-pad']);
  });

  it('splits a line or severity move into changed, and leaves true adds and removes', () => {
    const diff = diffFindingKeys(
      ['SAST-SQLI-001\tsrc/a.js\t10\thigh', 'SAST-XSS-001\tsrc/b.js\t2\tmedium'],
      ['SAST-SQLI-001\tsrc/a.js\t12\thigh', 'CONFIG-HELMET-001\tsrc/c.js\t1\tmedium'],
    );
    expect(diff.changed).toEqual([
      { from: 'SAST-SQLI-001\tsrc/a.js\t10\thigh', to: 'SAST-SQLI-001\tsrc/a.js\t12\thigh' },
    ]);
    expect(diff.removed).toEqual(['SAST-XSS-001\tsrc/b.js\t2\tmedium']);
    expect(diff.added).toEqual(['CONFIG-HELMET-001\tsrc/c.js\t1\tmedium']);
    expect(approvedDiffMatches('added\n', 'added')).toBe(true);
    expect(approvedDiffMatches('added\n', 'removed')).toBe(false);
    const text = formatSnapshotDiff([{ app: 'clean-app', ...diff }]);
    expect(text.startsWith('DRIFT clean-app\n')).toBe(true);
    expect(approvedDiffMatches(text, text)).toBe(true);
  });

  it('requests a new GitHub OIDC token and ignores a saved one', async () => {
    const calls: { url: string; auth: string }[] = [];
    const token = await githubOidcToken(
      {
        NPM_ID_TOKEN: 'stale.jwt.value',
        ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.test/token',
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token',
      },
      (url: URL | string, init?: { headers?: { Authorization?: string } }) => {
        calls.push({ url: String(url), auth: init?.headers?.Authorization ?? '' });
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ value: 'fresh.jwt.value' }),
        });
      },
    );
    expect(token).toBe('fresh.jwt.value');
    expect(calls[0]?.url).toContain('audience=npm%3Aregistry.npmjs.org');
    expect(calls[0]?.auth).toBe('Bearer request-token');
    const diagnose = readFileSync(join(process.cwd(), 'scripts/npm-oidc-diagnose.mjs'), 'utf8');
    const stage = readFileSync(join(process.cwd(), 'scripts/npm-stage-publish.mjs'), 'utf8');
    const publish = readFileSync(join(process.cwd(), '.github/workflows/publish.yml'), 'utf8');
    expect(diagnose).not.toContain('NPM_ID_TOKEN');
    expect(stage).not.toContain('NPM_ID_TOKEN');
    expect(publish).toContain('npm install -g npm@12.2.0');
  });

  it('treats a missing or empty attestation block as unpublished provenance', () => {
    expect(attestationsPresent({})).toBe(false);
    expect(attestationsPresent({ dist: {} })).toBe(false);
    expect(attestationsPresent({ dist: { attestations: {} } })).toBe(false);
    expect(attestationsPresent({ dist: { attestations: { url: 'https://example.test/a' } } })).toBe(true);
  });
});

describe('Phase 36 NoSQL BaseEntity', () => {
  it('does not flag TypeORM BaseEntity User.find when the file does not import typeorm', async () => {
    const code = [
      'class User extends BaseEntity {}',
      "app.post('/s', (req, res) => { User.find({ id: req.body.id }); });",
      '',
    ].join('\n');
    const hits = await runSastOnText('entity.js', code);
    expect(hits.some((f) => f.ruleId === 'SAST-NOSQLI-001')).toBe(false);
  });

  it('still flags a PascalCase User.find when the file is not a BaseEntity model', async () => {
    const hits = await runSastOnText(
      'mongo.js',
      "app.post('/s', (req, res) => { User.find(req.body); });",
    );
    expect(hits.some((f) => f.ruleId === 'SAST-NOSQLI-001')).toBe(true);
  });
});
