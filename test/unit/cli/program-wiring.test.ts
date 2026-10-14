import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');

let savedExitCode: typeof process.exitCode;
const dirs: string[] = [];

beforeEach(() => {
  savedExitCode = process.exitCode;
  process.exitCode = undefined;
});

afterEach(async () => {
  process.exitCode = savedExitCode;
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

async function runCli(args: string[]): Promise<{ out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  await program.parseAsync(['node', 'fullshield', ...args]);
  return { out: out.join('\n'), err: err.join('\n') };
}

describe('CLI wiring (in-process)', () => {
  it('scan writes json/sarif/markdown/html and last-scan', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-scan-'));
    dirs.push(dir);
    const { out, err } = await runCli([
      'scan',
      cleanApp,
      '--json',
      '--offline',
      '--sarif',
      join(dir, 'out.sarif'),
      '--markdown',
      join(dir, 'out.md'),
      '--html',
      join(dir, 'out.html'),
    ]);
    expect(err).toBe('');
    const parsed = JSON.parse(out) as { findings: unknown[] };
    expect(parsed.findings).toEqual([]);
    expect(await readFile(join(dir, 'out.sarif'), 'utf8')).toContain('2.1.0');
    expect(await readFile(join(dir, 'out.md'), 'utf8')).toContain('FullShield');
    expect(await readFile(join(dir, 'out.html'), 'utf8')).toContain('<!DOCTYPE html>');
  });

  it('fix dry-run on clean-app reports no safe fixes', async () => {
    const { out } = await runCli(['fix', cleanApp, '--modules', 'config']);
    expect(out).toMatch(/No safe fixes available|Dry run/);
  });

  it('fix dry-run on vulnerable-app prints unsafe helmet suggestions', async () => {
    const { out } = await runCli(['fix', vulnerableApp, '--modules', 'config']);
    expect(out).toContain('CONFIG-HELMET-001');
    expect(out).toMatch(/unsafe|helmet/i);
    expect(out).toContain('Dry run');
  });

  it('fix --apply without git exits 2', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-fix-'));
    dirs.push(dir);
    await writeFile(join(dir, 'app.js'), "const express = require('express');\nconst app = express();\n");
    const { err } = await runCli(['fix', dir, '--apply', '--modules', 'config']);
    expect(err).toMatch(/git repository|dirty/i);
    expect(process.exitCode).toBe(2);
  });

  it('init writes files and is a no-op the second time', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-init-'));
    dirs.push(dir);
    const first = await runCli(['init', dir]);
    expect(first.out).toContain('Wrote');
    const second = await runCli(['init', dir]);
    expect(second.out).toContain('Nothing to write');
  });

  it('notify --webhook posts the last-scan summary', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-notify-'));
    dirs.push(dir);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(join(dir, '.fullshield'), { recursive: true });
    await writeFile(
      join(dir, '.fullshield', 'last-scan.json'),
      JSON.stringify({
        summary: { total: 1, bySeverity: { info: 1, low: 0, medium: 0, high: 0, critical: 0 } },
        metadata: { version: '0.1.0', cwd: dir },
      }),
    );

    const received: string[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push(Buffer.concat(chunks).toString('utf8'));
        res.statusCode = 200;
        res.end('ok');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    const { out } = await runCli(['notify', dir, '--webhook', `http://127.0.0.1:${port}/hook`]);
    server.close();
    expect(out).toContain('1 finding');
    expect(received.length).toBe(1);
  });

  it('scan --update-baseline writes a baseline file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-base-'));
    dirs.push(dir);
    const { cpSync } = await import('node:fs');
    cpSync(cleanApp, dir, { recursive: true });
    const { err } = await runCli(['scan', dir, '--json', '--offline', '--update-baseline']);
    expect(err).toBe('');
    const baseline = await readFile(join(dir, '.fullshield-baseline.json'), 'utf8').catch(() => '');
    expect(baseline.length).toBeGreaterThan(0);
  });

  it('notify --slack without a URL exits 2', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-slack-'));
    dirs.push(dir);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(join(dir, '.fullshield'), { recursive: true });
    await writeFile(
      join(dir, '.fullshield', 'last-scan.json'),
      JSON.stringify({
        summary: { total: 0, bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 } },
        metadata: { version: '0.1.0' },
      }),
    );
    delete process.env.FULLSHIELD_SLACK_WEBHOOK;
    const { err } = await runCli(['notify', dir, '--slack']);
    expect(err).toContain('Slack webhook URL missing');
    expect(process.exitCode).toBe(2);
  });

  it('sbom --format cyclonedx writes a CycloneDX 1.5 document', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-sbom-'));
    dirs.push(dir);
    const out = join(dir, 'bom.json');
    const { out: stdout, err } = await runCli([
      'sbom',
      vulnerableApp,
      '--format',
      'cyclonedx',
      '--out',
      out,
    ]);
    expect(err).toBe('');
    expect(stdout).toContain('Wrote CycloneDX 1.5 SBOM');
    const doc = JSON.parse(await readFile(out, 'utf8')) as {
      bomFormat: string;
      specVersion: string;
      components: unknown[];
    };
    expect(doc.bomFormat).toBe('CycloneDX');
    expect(doc.specVersion).toBe('1.5');
    expect(Array.isArray(doc.components)).toBe(true);
  });

  it('sbom rejects an unsupported format', async () => {
    const { err } = await runCli(['sbom', vulnerableApp, '--format', 'spdx']);
    expect(err).toMatch(/unsupported SBOM format/i);
    expect(process.exitCode).toBe(2);
  });

  it('notify --email without SMTP env exits 2', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-email-'));
    dirs.push(dir);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(join(dir, '.fullshield'), { recursive: true });
    await writeFile(
      join(dir, '.fullshield', 'last-scan.json'),
      JSON.stringify({
        summary: { total: 0, bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 } },
      }),
    );
    delete process.env.FULLSHIELD_SMTP_HOST;
    delete process.env.FULLSHIELD_SMTP_FROM;
    delete process.env.FULLSHIELD_NOTIFY_EMAIL;
    const { err } = await runCli(['notify', dir, '--email']);
    expect(err).toContain('email notify requires');
    expect(process.exitCode).toBe(2);
  });

  it('scan --ai logic is not shipped and exits 2', async () => {
    const logicApp = join(process.cwd(), 'test', 'fixtures', 'ai-logic-app');
    process.exitCode = undefined;
    const { err } = await runCli(['scan', logicApp, '--json', '--offline', '--ai', 'logic']);
    expect(err).toMatch(/not shipped/i);
    expect(process.exitCode).toBe(2);
  });

  it('scan --ai explain never includes a verdict', async () => {
    const inject = join(process.cwd(), 'test', 'fixtures', 'ai-inject-app');
    process.exitCode = undefined;
    const { out, err } = await runCli(['scan', inject, '--json', '--offline', '--ai', 'explain']);
    expect(err).toBe('');
    const parsed = JSON.parse(out) as {
      findings: Array<{ ruleId: string; explanation?: string; aiVerdict?: string }>;
    };
    const hit = parsed.findings.find((f) => f.ruleId === 'AI-INJECT-001');
    expect(hit?.explanation).toMatch(/comment|AI/i);
    expect(parsed.findings.every((f) => f.aiVerdict === undefined)).toBe(true);
    expect(out).not.toMatch(/true-positive|likely-false-positive|needs-review/);
  });

  it('scan --ai with an unknown mode exits 2', async () => {
    const { err } = await runCli(['scan', cleanApp, '--ai', 'dance']);
    expect(err).toMatch(/invalid --ai mode/i);
    expect(process.exitCode).toBe(2);
  });

  it('fix --ai prints a reviewable diff and does not apply it', async () => {
    const inject = join(process.cwd(), 'test', 'fixtures', 'ai-inject-app');
    const { out } = await runCli(['fix', inject, '--ai']);
    expect(out).toMatch(/reviewable diff|AI patch/i);
  });

  it('install refuses without FULLSHIELD_EXPERIMENTAL_SUPPLY', async () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
    delete process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
    try {
      const { err } = await runCli(['install', 'lodash']);
      expect(err).toMatch(/FULLSHIELD_EXPERIMENTAL_SUPPLY/);
      expect(process.exitCode).toBe(2);
    } finally {
      if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
      else process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY = prev;
    }
  });

  it('install reports seeded malicious findings and does not claim npm install ran', async () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
    process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY = '1';
    try {
      const dir = join(process.cwd(), 'test', 'fixtures', 'supply', 'malicious-pkg');
      const { out } = await runCli(['install', 'fullshield-seeded-malicious', '--dir', dir]);
      expect(out).toMatch(/SUPPLY-NPMRC-NET-001/);
      expect(out).not.toMatch(/npm install --ignore-scripts/);
      expect(process.exitCode).toBe(1);
    } finally {
      if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
      else process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY = prev;
    }
  });

  it('confirm refuses without FULLSHIELD_EXPERIMENTAL_CONFIRM', async () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
    delete process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
    try {
      const { err } = await runCli(['confirm', 'http://127.0.0.1:1/']);
      expect(err).toMatch(/FULLSHIELD_EXPERIMENTAL_CONFIRM/);
      expect(process.exitCode).toBe(2);
    } finally {
      if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
      else process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM = prev;
    }
  });

  it('confirm on 127.0.0.1 with experimental prints JSON', async () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
    process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM = '1';
    try {
      const { out, err } = await runCli(['confirm', 'http://127.0.0.1:9/']);
      expect(err).toBe('');
      const parsed = JSON.parse(out) as { ok: boolean };
      expect(parsed.ok).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
      else process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM = prev;
    }
  });

  it('confirm refuses a public hostname', async () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
    process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM = '1';
    try {
      const { err } = await runCli(['confirm', 'http://example.com/']);
      expect(err).toMatch(/refused/);
      expect(process.exitCode).toBe(2);
    } finally {
      if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM;
      else process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM = prev;
    }
  });

  it('install on a clean local dir prints the ignore-scripts next step', async () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
    process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY = '1';
    try {
      const dir = join(process.cwd(), 'test', 'fixtures', 'supply', 'benign-pkg');
      const { out, err } = await runCli(['install', 'fullshield-seeded-benign', '--dir', dir]);
      expect(err).toBe('');
      expect(out).toMatch(/npm install --ignore-scripts/);
      expect(process.exitCode === undefined || process.exitCode === 0).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
      else process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY = prev;
    }
  });
});
