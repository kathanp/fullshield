import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { nodeOk, runDoctor } from '../../../src/cli/commands/doctor.js';
import { createProgram } from '../../../src/cli/program.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { formatCliError } from '../../../src/cli/errors.js';
import type { ScanResult } from '../../../src/core/engine.js';

describe('Phase 44 developer experience', () => {
  it('doctor reports node, lockfile, config, and offline OSV', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-doctor-'));
    writeFileSync(join(dir, 'package-lock.json'), '{}\n');
    writeFileSync(join(dir, 'fullshield.config.json'), '{"failOn":"high"}\n');
    let out = '';
    const program = createProgram({
      out: (text) => {
        out += text;
      },
      err: () => {},
    });
    await program.parseAsync(['node', 'fullshield', 'doctor', dir, '--offline']);
    expect(out).toContain('node:');
    expect(out).toContain('lockfile: package-lock.json');
    expect(out).toContain('config: valid');
    expect(out).toContain('osv: network skipped (--offline)');
  });

  it('reports a missing lockfile, an invalid config, and a set flag', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-doctor-empty-'));
    writeFileSync(join(dir, 'fullshield.config.json'), '{"failOn":1}\n');
    process.env.FULLSHIELD_EXPERIMENTAL_TAINT_V2 = '1';
    try {
      const text = await runDoctor(dir);
      expect(text).toContain('lockfile: none');
      expect(text).toContain('config: invalid');
      expect(text).toContain('FULLSHIELD_EXPERIMENTAL_TAINT_V2');
      expect(text).toContain('osv: network allowed');
    } finally {
      delete process.env.FULLSHIELD_EXPERIMENTAL_TAINT_V2;
    }
    expect(nodeOk('22.13.0')).toBe(true);
    expect(nodeOk('20.11.0')).toBe(true);
    expect(nodeOk('20.10.9')).toBe(false);
    expect(nodeOk('24')).toBe(true);
    expect(formatCliError('plain failure', false)).toContain('FS-E000');
  });

  it('prefixes a known error and hides the stack unless --debug is set', () => {
    const error = new Error('invalid --fail-on severity "severe" (valid: high)');
    error.stack = 'Error: invalid\n    at hidden (cli.js:1:1)';
    const plain = formatCliError(error, false);
    expect(plain).toContain('FS-E001');
    expect(plain).toContain('invalid --fail-on severity "severe"');
    expect(plain).not.toContain('at hidden');
    expect(formatCliError(error, true)).toContain('at hidden');
  });

  it('shows at most 10 findings and points at --json', () => {
    const findings = Array.from({ length: 12 }, (_, i) => ({
      id: `id-${i}`,
      ruleId: 'SAST-SQLI-001',
      module: 'sast' as const,
      title: 'SQL injection',
      severity: 'high' as const,
      confidence: 'high' as const,
      file: `a${i}.js`,
      line: i + 1,
      message: 'query is built from request data',
      remediation: 'use a placeholder',
    }));
    const result = {
      findings,
      summary: { total: 12, bySeverity: { info: 0, low: 0, medium: 0, high: 12, critical: 0 } },
      metadata: {
        version: '0.1.3',
        filesScanned: 1,
        durationMs: 1,
        modulesRequested: ['sast'],
        modulesRun: ['sast'],
      },
    } as ScanResult;
    const text = renderConsoleReport(result);
    expect(text).toContain('2 more — use --json');
    expect(text).toContain('docs: rules/SAST-SQLI-001.md');
    expect(text).toContain('a0.js:1');
    expect(text).not.toContain('a11.js');
  });
});
