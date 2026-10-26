import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { mailFindings, mailOnFiles } from '../../../../src/modules/sast/mail.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_MAIL';
const nodemailer = "const mail = require('nodemailer');\n";

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 533 mail header injection', () => {
  it('registers scan --experimental-mail', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-mail');
  });

  it('fires when a mail field is request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${nodemailer}function go(req) { mail.sendMail({ subject: req.query.subject }); }\n`);
    const mail = hits.filter((finding) => finding.ruleId === 'SAST-MAIL-001');
    expect(mail).toHaveLength(1);
    expect(mail[0]?.severity).toBe('high');
    expect(mail[0]?.cwe).toBe('CWE-93');
    expect(mail[0]?.line).toBe(2);
    expect(await ids("const sg = require('@sendgrid/mail');\nfunction go(req) { sg.send({ to: req.body.to }); }\n")).toContain('SAST-MAIL-001');
    expect(await ids("const mg = require('mailgun.js');\nfunction go(req) { mg.sendMail({ html: req.params.html }); }\n")).toContain('SAST-MAIL-001');
    expect(await ids(`${nodemailer}function go(req) { mail.send({ cc: req.query.cc, bcc: req.headers.bcc }); }\n`)).toContain('SAST-MAIL-001');
    expect(await ids(`${nodemailer}function go(req) { mail.sendMail({ from: req.query.from, replyTo: req.query.reply, text: req.body.text }); }\n`)).toContain('SAST-MAIL-001');
  });

  it('stays silent for a literal field, a missing import, and a non-mail argument', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${nodemailer}function go(req) { mail.sendMail({ subject: 'hello' }); }\n`)).not.toContain('SAST-MAIL-001');
    expect(await ids('function go(req) { mail.sendMail({ subject: req.query.subject }); }\n')).not.toContain('SAST-MAIL-001');
    expect(await ids(`${nodemailer}function go(req) { res.send(req.body); }\n`)).not.toContain('SAST-MAIL-001');
    expect(await ids(`${nodemailer}function go(req) { mail.sendMail(...req.query.parts); }\n`)).not.toContain('SAST-MAIL-001');
    expect(await ids(`${nodemailer}function go(req) { mail.sendMail({ note: req.query.subject }); }\n`)).not.toContain('SAST-MAIL-001');
    expect(await ids(`${nodemailer}function go(req) { mail.sendMail({ [req.query.k]: req.query.v }); }\n`)).not.toContain('SAST-MAIL-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids(`${nodemailer}function go(req) { mail.sendMail({ subject: req.query.subject }); }\n`)).not.toContain('SAST-MAIL-001');
    process.env[FLAG] = '1';
    expect(await mailFindings('fixture.js', "const mail = require('nodemailer'); {{{")).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-mail-'));
    expect(await mailOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${nodemailer}function go(req) { mail.sendMail({ subject: req.query.subject }); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
