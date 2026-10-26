import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { browserCtlFindings, browserCtlOnFiles } from '../../../../src/modules/sast/browserCtl.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const vulnerableApp = join(import.meta.dirname, '../../../fixtures/vulnerable-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_BROWSER';

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((finding) => `${finding.ruleId}|${finding.file ?? ''}|${finding.line ?? ''}|${finding.severity}`).sort();
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 535 browser-automation control', () => {
  it('registers scan --experimental-browser', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-browser');
  });

  it('fires when browser automation is passed request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', "const puppeteer = require('puppeteer');\nfunction go(req) { page.goto(req.query.url); }\n");
    const browser = hits.filter((finding) => finding.ruleId === 'SAST-BROWSER-001');
    expect(browser).toHaveLength(1);
    expect(browser[0]?.severity).toBe('high');
    expect(browser[0]?.cwe).toBe('CWE-918');
    expect(browser[0]?.line).toBe(2);
    const html = await runSastOnText('fixture.js', "const puppeteer = require('puppeteer-core');\nfunction go(req) { page.setContent(req.body.html); }\n");
    expect(html.find((finding) => finding.ruleId === 'SAST-BROWSER-001')?.cwe).toBe('CWE-79');
    const pdf = await runSastOnText('fixture.js', "const pw = require('playwright');\nfunction go(req) { page.pdf({ path: req.query.out }); }\n");
    expect(pdf.find((finding) => finding.ruleId === 'SAST-BROWSER-001')?.cwe).toBe('CWE-918');
    expect(await ids("const pw = require('@playwright/test');\nfunction go(req) { page.goto(req.params.url); }\n")).toContain('SAST-BROWSER-001');
  });

  it('stays silent for a literal URL, a missing import, and a call with no argument', async () => {
    process.env[FLAG] = '1';
    expect(await ids("const puppeteer = require('puppeteer');\nfunction go(req) { page.goto('https://example.com'); }\n")).not.toContain('SAST-BROWSER-001');
    expect(await ids('function go(req) { page.goto(req.query.url); }\n')).not.toContain('SAST-BROWSER-001');
    expect(await ids("const puppeteer = require('puppeteer');\nfunction go(req) { page.pdf(); }\n")).not.toContain('SAST-BROWSER-001');
    expect(await ids("const puppeteer = require('puppeteer');\nfunction go(req) { page.goto(...req.query.parts); }\n")).not.toContain('SAST-BROWSER-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids("const puppeteer = require('puppeteer');\nfunction go(req) { page.goto(req.query.url); }\n")).not.toContain('SAST-BROWSER-001');
    process.env[FLAG] = '1';
    expect(await browserCtlFindings('fixture.js', "const puppeteer = require('puppeteer'); {{{")).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-browserctl-'));
    expect(await browserCtlOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps vulnerable-app and clean-app unchanged with the flag on', async () => {
    delete process.env[FLAG];
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
    expect(onClean.findings.filter((finding) => finding.ruleId === 'SAST-BROWSER-001')).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = "const puppeteer = require('puppeteer');\nfunction go(req) { page.goto(req.query.url); }\n";
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
