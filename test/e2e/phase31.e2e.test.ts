import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const vexApp = join(root, 'test', 'fixtures', 'vex-app');
const NEW_IDS = ['SUPPLY-WORM-001', 'SUPPLY-WORKFLOW-001'];

describe('Phase 31 CLI (built)', () => {
  it('default scan of vulnerable-app does not emit new Phase 31 IDs', () => {
    const result = spawnSync(
      process.execPath,
      [cli, 'scan', vulnerableApp, '--json', '--modules', 'deps', '--offline'],
      {
        cwd: root,
        encoding: 'utf8',
        env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '' },
      },
    );
    const report = JSON.parse(result.stdout) as { findings: Array<{ ruleId: string }> };
    expect(report.findings.some((f) => NEW_IDS.includes(f.ruleId))).toBe(false);
  });

  it('refuses vex without FULLSHIELD_EXPERIMENTAL_VEX', () => {
    const result = spawnSync(process.execPath, [cli, 'vex', vexApp, '--format', 'openvex'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '' },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/FULLSHIELD_EXPERIMENTAL_VEX/);
  });

  it('emits schema-valid OpenVEX and CycloneDX when the flag is set', () => {
    const open = spawnSync(process.execPath, [cli, 'vex', vexApp, '--format', 'openvex'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '1' },
    });
    expect(open.status).toBe(0);
    const openDoc = JSON.parse(open.stdout) as {
      statements: Array<{ status: string; justification?: string }>;
    };
    expect(openDoc.statements.length).toBeGreaterThan(0);
    expect(
      openDoc.statements.every(
        (s) =>
          s.status === 'under_investigation' ||
          (s.status === 'not_affected' && s.justification === 'vulnerable_code_not_in_execute_path'),
      ),
    ).toBe(true);

    const cdx = spawnSync(process.execPath, [cli, 'vex', vexApp, '--format', 'cyclonedx'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VEX: '1' },
    });
    expect(cdx.status).toBe(0);
    const cdxDoc = JSON.parse(cdx.stdout) as {
      bomFormat: string;
      specVersion: string;
      vulnerabilities: Array<{ analysis: { state: string } }>;
    };
    expect(cdxDoc.bomFormat).toBe('CycloneDX');
    expect(cdxDoc.specVersion).toBe('1.5');
    expect(cdxDoc.vulnerabilities.length).toBeGreaterThan(0);
  });
});
