import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, GHA_CACHE, GHA_INJECT, GHA_TARGET, scanWorkflow } from '../../../src/phases/p454.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('phase 454', () => {
  it('reports a pull request title inside run and not github.repository', () => {
    process.env[FLAG] = '1';
    const bad = scanWorkflow('ci.yml', 'jobs:\n  t:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n');
    expect(bad.some((row) => row.ruleId === GHA_INJECT)).toBe(true);
    const good = scanWorkflow('ci.yml', 'jobs:\n  t:\n    steps:\n      - run: echo ${{ github.repository }}\n');
    expect(good.some((row) => row.ruleId === GHA_INJECT)).toBe(false);
  });

  it('reports pull_request_target with the PR head and not a sha-only cache key', () => {
    process.env[FLAG] = '1';
    const target = `on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`;
    const findings = scanWorkflow('ci.yml', target);
    expect(findings.some((row) => row.ruleId === GHA_TARGET)).toBe(true);
    expect(findings.find((row) => row.ruleId === GHA_TARGET)?.message).toContain('executing the PR');
    expect(findings.find((row) => row.ruleId === GHA_TARGET)?.message).not.toContain('already compromised');
    const cache = scanWorkflow('ci.yml', 'jobs:\n  t:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          key: ${{ github.sha }}\n');
    expect(cache.some((row) => row.ruleId === GHA_CACHE)).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'ci.yml', line: 1, message: 'kept' }];
    const text = 'jobs:\n  t:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n';
    expect(scanWorkflow('ci.yml', text, {}, baseline)).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p454.ts'), 'utf8');
    expect(src.includes('node:http')).toBe(false);
  });

  it('covers string triggers, nested expressions, cache keys, and env artifacts', () => {
    process.env[FLAG] = '1';
    const token = `AKIA${'Z'.repeat(16)}`;
    try {
      expect(scanWorkflow('ci.yml', '[]\n')).toEqual([]);
      expect(scanWorkflow('ci.yml', 'hello\n')).toEqual([]);
      expect(scanWorkflow('ci.yml', '')).toEqual([]);
      const target = scanWorkflow(
        'ci.yml',
        'on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n',
      );
      expect(target.some((row) => row.ruleId === GHA_TARGET)).toBe(true);
      const listed = scanWorkflow(
        'ci.yml',
        'on:\n  - push\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n',
      );
      expect(listed.some((row) => row.ruleId === GHA_TARGET)).toBe(false);
      const nested = scanWorkflow('ci.yml', 'jobs:\n  t:\n    steps:\n      - run: echo ${{ ${{ github.event.name }} }}\n      - run: echo hello\n');
      expect(nested.some((row) => row.ruleId === GHA_INJECT)).toBe(true);
      const cache = scanWorkflow(
        'ci.yml',
        'jobs:\n  t:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          key: ${{ github.event.pull_request.head.ref }}\n          path: dist\n',
      );
      expect(cache.some((row) => row.ruleId === GHA_CACHE)).toBe(true);
      const info = scanWorkflow('ci.yml', 'jobs:\n  t:\n    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          path: .env\n');
      expect(info.some((row) => row.ruleId === 'CI-GHA-ARTIFACT-001' && row.severity === 'info')).toBe(true);
      const secret = scanWorkflow(
        'ci.yml',
        'jobs:\n  t:\n    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          path: build/.env\n',
        { 'build/.env': token },
      );
      expect(secret.some((row) => row.ruleId === 'SECRET-AWS-001')).toBe(true);
      expect(JSON.stringify(secret)).not.toContain(token);
      const plain = scanWorkflow(
        'ci.yml',
        'true:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n          path: dist\n          key: 1\n',
      );
      expect(plain.some((row) => row.ruleId === GHA_TARGET)).toBe(false);
      expect(plain.some((row) => row.ruleId === 'CI-GHA-ARTIFACT-001')).toBe(false);
    } finally {
      delete process.env[FLAG];
    }
  });
});
