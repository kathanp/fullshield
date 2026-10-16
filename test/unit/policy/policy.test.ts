import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyBaseline } from '../../../src/core/baseline.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';
import { scan } from '../../../src/core/engine.js';
import {
  POLICY_FILE_NAME,
  POLICY_PEER_ERROR,
  PolicyError,
  applyPolicy,
  isPolicyEnabled,
  loadPolicy,
  parsePolicy,
} from '../../../src/policy/index.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_POLICY';
const vulnApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

function finding(ruleId: string, overrides: Partial<Finding> = {}): Finding {
  const file = overrides.file ?? 'src/a.js';
  return {
    id: makeFindingId(ruleId, file, overrides.snippet ?? ruleId),
    ruleId,
    module: 'sast',
    title: ruleId,
    severity: 'high',
    confidence: 'high',
    file,
    line: 1,
    message: ruleId,
    remediation: 'fix',
    ...overrides,
  };
}

let dir: string;
let savedFlag: string | undefined;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-policy-'));
  savedFlag = process.env[FLAG];
  delete process.env[FLAG];
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  if (savedFlag === undefined) delete process.env[FLAG];
  else process.env[FLAG] = savedFlag;
});

async function writePolicy(body: unknown): Promise<string> {
  const path = join(dir, POLICY_FILE_NAME);
  await writeFile(path, `${JSON.stringify(body, null, 2)}\n`, 'utf8');
  return path;
}

async function writeSqliApp(): Promise<void> {
  await writeFile(
    join(dir, 'fullshield.config.json'),
    `${JSON.stringify({ modules: ['sast'], failOn: 'high', ignore: ['node_modules/**'] })}\n`,
  );
  await mkdir(join(dir, 'src'), { recursive: true });
  await writeFile(
    join(dir, 'src', 'index.js'),
    [
      "const express = require('express');",
      'const db = { query() {} };',
      'const app = express();',
      "app.get('/user', (req, res) => {",
      "  db.query('SELECT * FROM users WHERE id = ' + req.query.id);",
      '  res.end();',
      '});',
      '',
    ].join('\n'),
    'utf8',
  );
}

describe('isPolicyEnabled', () => {
  it('is off by default and on with the experimental flag or explicit opt-in', () => {
    expect(isPolicyEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(isPolicyEnabled()).toBe(true);
    delete process.env[FLAG];
    expect(isPolicyEnabled({ experimental: true })).toBe(true);
  });
});

describe('parsePolicy (zod schema)', () => {
  it('accepts required modules, severity overrides, failOn per branch, and complete exceptions', async () => {
    const policy = await parsePolicy({
      requiredModules: ['secrets', 'sast'],
      severityOverrides: { 'SAST-AUTH-001': 'low' },
      failOn: { main: 'medium', '*': 'high' },
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          file: 'src/legacy.js',
          owner: 'alice@example.com',
          reason: 'tracked in INC-123',
          expires: '2099-12-31',
        },
      ],
    });
    expect(policy.requiredModules).toEqual(['secrets', 'sast']);
    expect(policy.severityOverrides?.['SAST-AUTH-001']).toBe('low');
    expect(policy.failOn?.main).toBe('medium');
    expect(policy.exceptions?.[0]?.owner).toBe('alice@example.com');
  });

  it('rejects exceptions without an owner', async () => {
    await expect(
      parsePolicy({
        exceptions: [{ ruleId: 'SAST-SQLI-001', reason: 'later', expires: '2099-01-01' }],
      }),
    ).rejects.toThrow(PolicyError);
    await expect(
      parsePolicy({
        exceptions: [{ ruleId: 'SAST-SQLI-001', reason: 'later', expires: '2099-01-01' }],
      }),
    ).rejects.toThrow(/owner/);
  });

  it('rejects exceptions without an expiry', async () => {
    await expect(
      parsePolicy({
        exceptions: [{ ruleId: 'SAST-SQLI-001', owner: 'alice', reason: 'later' }],
      }),
    ).rejects.toThrow(/expires/);
  });

  it('rejects exceptions without a reason', async () => {
    await expect(
      parsePolicy({
        exceptions: [{ ruleId: 'SAST-SQLI-001', owner: 'alice', expires: '2099-01-01' }],
      }),
    ).rejects.toThrow(/reason/);
  });

  it('rejects a non-ISO expires value', async () => {
    await expect(
      parsePolicy({
        exceptions: [
          { ruleId: 'SAST-SQLI-001', owner: 'alice', reason: 'later', expires: 'next Friday' },
        ],
      }),
    ).rejects.toThrow(/ISO|expires/i);
  });

  it('rejects an empty owner string', async () => {
    await expect(
      parsePolicy({
        exceptions: [
          { ruleId: 'SAST-SQLI-001', owner: '', reason: 'later', expires: '2099-01-01' },
        ],
      }),
    ).rejects.toThrow(/owner/);
  });

  it('throws a clear install hint when the optional zod peer cannot be imported', async () => {
    await expect(
      parsePolicy({}, POLICY_FILE_NAME, () => Promise.reject(new Error('Cannot find package zod'))),
    ).rejects.toThrow(POLICY_PEER_ERROR);
  });
});

describe('loadPolicy', () => {
  it('returns undefined without the flag even when a policy file exists', async () => {
    await writePolicy({ requiredModules: ['sast'] });
    expect(await loadPolicy(dir)).toBeUndefined();
  });

  it('returns undefined when the flag is on but no policy file exists', async () => {
    process.env[FLAG] = '1';
    expect(await loadPolicy(dir)).toBeUndefined();
  });

  it('loads and validates a policy file when the flag is on', async () => {
    process.env[FLAG] = '1';
    await writePolicy({ failOn: { '*': 'medium' } });
    const loaded = await loadPolicy(dir);
    expect(loaded?.failOn?.['*']).toBe('medium');
  });
});

describe('applyPolicy', () => {
  const now = new Date('2026-10-15T12:00:00.000Z');

  it('overrides severity per rule id', () => {
    const applied = applyPolicy([finding('SAST-AUTH-001')], {
      severityOverrides: { 'SAST-AUTH-001': 'low' },
    });
    expect(applied.findings[0]?.severity).toBe('low');
    expect(applied.errors).toEqual([]);
  });

  it('suppresses a matching exception that has not expired', () => {
    const hit = finding('SAST-SQLI-001', { file: 'src/legacy.js' });
    const other = finding('SAST-EVAL-001', { file: 'src/ok.js' });
    const applied = applyPolicy([hit, other], {
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          file: 'src/legacy.js',
          owner: 'alice',
          reason: 'queued',
          expires: '2099-12-31',
        },
      ],
    }, { now });
    expect(applied.findings.map((f) => f.ruleId)).toEqual(['SAST-EVAL-001']);
    expect(applied.errors).toEqual([]);
  });

  it('does not suppress an expired exception and records a clear CI error', () => {
    const hit = finding('SAST-SQLI-001', { file: 'src/legacy.js' });
    const applied = applyPolicy([hit], {
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          file: 'src/legacy.js',
          owner: 'alice',
          reason: 'queued',
          expires: '2020-01-01',
        },
      ],
    }, { now });
    expect(applied.findings.map((f) => f.ruleId)).toEqual(['SAST-SQLI-001']);
    expect(applied.errors).toHaveLength(1);
    expect(applied.errors[0]).toMatch(/expired on 2020-01-01/);
    expect(applied.errors[0]).toMatch(/alice/);
    expect(applied.errors[0]).toMatch(/SAST-SQLI-001/);
    expect(applied.errors[0]).toMatch(/renew or remove/i);
  });

  it('selects failOn for the current branch, then *', () => {
    const policy = { failOn: { main: 'low' as const, '*': 'critical' as const } };
    expect(applyPolicy([], policy, { branch: 'main' }).failOn).toBe('low');
    expect(applyPolicy([], policy, { branch: 'feature/x' }).failOn).toBe('critical');
  });

  it('records a CI error when a required module did not run', () => {
    const applied = applyPolicy([], { requiredModules: ['secrets', 'sast'] }, {
      modulesRun: ['sast'],
    });
    expect(applied.errors.some((e) => /required module "secrets"/.test(e))).toBe(true);
  });

  it('composes with baseline: exceptions apply to remaining findings', () => {
    const oldOne = finding('SAST-SQLI-001', { file: 'a.js' });
    const fresh = finding('SAST-EVAL-001', { file: 'b.js' });
    const remaining = applyBaseline([oldOne, fresh], {
      version: 1,
      findings: [{ id: oldOne.id, ruleId: oldOne.ruleId, file: oldOne.file, line: oldOne.line }],
    });
    const applied = applyPolicy(remaining, {
      exceptions: [
        {
          ruleId: 'SAST-EVAL-001',
          owner: 'bob',
          reason: 'accepted',
          expires: '2099-01-01',
        },
      ],
    }, { now });
    expect(applied.findings).toEqual([]);
  });
});

describe('scan + policy (experimental)', () => {
  it('default scan without the flag or a policy file adds no POLICY ids on vulnerable-app or clean-app', async () => {
    const vuln = await scan({ cwd: vulnApp, offline: true });
    const clean = await scan({ cwd: cleanApp, offline: true });
    expect(vuln.findings.some((f) => f.ruleId.startsWith('POLICY-'))).toBe(false);
    expect(clean.findings.some((f) => f.ruleId.startsWith('POLICY-'))).toBe(false);
    expect(clean.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')).toEqual(
      [],
    );

    process.env[FLAG] = '1';
    const vulnFlag = await scan({ cwd: vulnApp, offline: true, experimentalPolicy: true });
    const cleanFlag = await scan({ cwd: cleanApp, offline: true, experimentalPolicy: true });
    expect(vulnFlag.findings.map((f) => f.id).sort()).toEqual(vuln.findings.map((f) => f.id).sort());
    expect(cleanFlag.findings.map((f) => f.id).sort()).toEqual(clean.findings.map((f) => f.id).sort());
  });

  it('an expired exception fails the scan policy gate and does not hide the finding', async () => {
    await writeSqliApp();
    await writePolicy({
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          owner: 'alice',
          reason: 'forgot to renew',
          expires: '2020-01-01',
        },
      ],
    });
    process.env[FLAG] = '1';
    const result = await scan({ cwd: dir, experimentalPolicy: true, modules: ['sast'] });
    expect(result.findings.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(result.policy?.errors.some((e) => /expired on 2020-01-01/.test(e))).toBe(true);
  });

  it('a current exception suppresses the matching finding', async () => {
    await writeSqliApp();
    await writePolicy({
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          owner: 'alice',
          reason: 'tracked',
          expires: '2099-12-31',
        },
      ],
    });
    process.env[FLAG] = '1';
    const result = await scan({ cwd: dir, experimentalPolicy: true, modules: ['sast'] });
    expect(result.findings.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(false);
    expect(result.policy?.errors ?? []).toEqual([]);
  });

  it('requiredModules are added to the scan and severity overrides apply', async () => {
    await writeSqliApp();
    await writePolicy({
      requiredModules: ['sast'],
      severityOverrides: { 'SAST-SQLI-001': 'info' },
    });
    process.env[FLAG] = '1';
    const result = await scan({
      cwd: dir,
      experimentalPolicy: true,
      modules: ['secrets'],
    });
    expect(result.metadata.modulesRequested).toEqual(expect.arrayContaining(['secrets', 'sast']));
    const sqli = result.findings.find((f) => f.ruleId === 'SAST-SQLI-001');
    expect(sqli?.severity).toBe('info');
  });

  it('failOn follows the policy branch map', async () => {
    await writeSqliApp();
    await writePolicy({ failOn: { main: 'critical', '*': 'info' } });
    process.env[FLAG] = '1';
    const onMain = await scan({
      cwd: dir,
      experimentalPolicy: true,
      modules: ['sast'],
      policyBranch: 'main',
    });
    expect(onMain.policy?.failOn).toBe('critical');
    const onFeat = await scan({
      cwd: dir,
      experimentalPolicy: true,
      modules: ['sast'],
      policyBranch: 'feature/x',
    });
    expect(onFeat.policy?.failOn).toBe('info');
  });

  it('ignores a policy file when the experimental flag is off', async () => {
    await writeSqliApp();
    await writePolicy({
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          owner: 'alice',
          reason: 'tracked',
          expires: '2099-12-31',
        },
      ],
    });
    const result = await scan({ cwd: dir, modules: ['sast'] });
    expect(result.findings.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(result.policy).toBeUndefined();
  });
});
