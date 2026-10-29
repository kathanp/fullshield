import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { formatCliError } from '../../../src/cli/errors.js';
import { scan } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { applyExceptions, loadExceptions, parseExceptions } from '../../../src/policy/exceptions.js';

const now = new Date('2026-01-01T00:00:00.000Z');
const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_EXCEPTIONS;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function finding(): Finding {
  return {
    id: 'abc',
    ruleId: 'DEPS-NOLOCK-001',
    module: 'deps',
    title: 'No lockfile found',
    severity: 'info',
    confidence: 'high',
    file: 'package.json',
    message: 'No lockfile found',
    remediation: 'Commit a lockfile',
  };
}

describe('phase 562 exception file', () => {
  it('suppresses a valid row and fails an expired row without suppressing it', () => {
    const row = { ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '2026-06-01' };
    const applied = applyExceptions([finding()], [row], now);
    expect(applied.findings).toEqual([]);
    expect(applied.errors).toEqual([]);
    const expired = applyExceptions([finding()], [{ ...row, expires: '2025-12-31' }], now);
    expect(expired.findings).toHaveLength(1);
    expect(expired.errors[0]).toMatch(/expired/);
  });

  it('accepts an expiry inside 365 days and rejects one past it', () => {
    const row = { ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '2026-12-31' };
    expect(applyExceptions([finding()], [row], now).findings).toEqual([]);
    expect(() => applyExceptions([finding()], [{ ...row, expires: '2027-01-01' }], now)).toThrow(/365 days/);
    expect(formatCliError(new Error('exceptions file expiry exceeds 365 days (FULLSHIELD_EXPERIMENTAL_EXCEPTIONS)'))).toMatch(/FS-E022/);
  });

  it('rejects a row with no owner and ignores the file when the flag is off', async () => {
    expect(() => parseExceptions({ exceptions: [{ ruleId: 'DEPS-NOLOCK-001', reason: 'x', expires: '2026-06-01' }] })).toThrow(/owner, reason, and expires/);
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-exc-'));
    dirs.push(dir);
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'exc' }), 'utf8');
    await writeFile(
      join(dir, 'fullshield.exceptions.json'),
      JSON.stringify({ exceptions: [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '2027-04-01' }] }),
      'utf8',
    );
    const off = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(off.findings.some((row) => row.ruleId === 'DEPS-NOLOCK-001')).toBe(true);
    process.env.FULLSHIELD_EXPERIMENTAL_EXCEPTIONS = '1';
    const on = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(on.findings.some((row) => row.ruleId === 'DEPS-NOLOCK-001')).toBe(false);
    expect(await loadExceptions(dir)).toHaveLength(1);
  });

  it('rejects a broken exceptions document and a timestamp expiry', async () => {
    expect(() => parseExceptions(null)).toThrow(/must be an object/);
    expect(() => parseExceptions({})).toThrow(/requires exceptions/);
    expect(() => parseExceptions({ exceptions: [null] })).toThrow(/owner, reason, and expires/);
    expect(() => parseExceptions({ exceptions: [{ ruleId: '', owner: 'ada', reason: 'ticket', expires: '2026-06-01' }] })).toThrow(/owner, reason, and expires/);
    expect(() => parseExceptions({ exceptions: [{ ruleId: 'DEPS-NOLOCK-001', owner: '', reason: 'ticket', expires: '2026-06-01' }] })).toThrow(/owner, reason, and expires/);
    expect(() => parseExceptions({ exceptions: [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: '', expires: '2026-06-01' }] })).toThrow(/owner, reason, and expires/);
    expect(() => parseExceptions({ exceptions: [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '' }] })).toThrow(/owner, reason, and expires/);
    expect(() => parseExceptions({ exceptions: [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '2026-06-01', file: '' }] })).toThrow(/owner, reason, and expires/);
    expect(() => applyExceptions([finding()], [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: 'not-a-date' }], now)).toThrow(/ISO date/);
    const stamped = applyExceptions(
      [finding()],
      [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '2026-06-01T12:00:00.000Z' }],
      now,
    );
    expect(stamped.findings).toEqual([]);
    const empty = await mkdtemp(join(tmpdir(), 'fullshield-exc-empty-'));
    dirs.push(empty);
    expect(await loadExceptions(empty)).toBeUndefined();
    const bad = await mkdtemp(join(tmpdir(), 'fullshield-exc-bad-'));
    dirs.push(bad);
    await writeFile(join(bad, 'fullshield.exceptions.json'), '{', 'utf8');
    await expect(loadExceptions(bad)).rejects.toThrow(/not JSON/);
    const blocked = await mkdtemp(join(tmpdir(), 'fullshield-exc-dir-'));
    dirs.push(blocked);
    await mkdir(join(blocked, 'fullshield.exceptions.json'));
    await expect(loadExceptions(blocked)).rejects.toThrow(/cannot read exceptions file/);
  });

  it('does not suppress a different file', () => {
    const applied = applyExceptions(
      [finding()],
      [{ ruleId: 'DEPS-NOLOCK-001', owner: 'ada', reason: 'ticket', expires: '2026-06-01', file: 'other.json' }],
      now,
    );
    expect(applied.findings).toHaveLength(1);
  });
});
