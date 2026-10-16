import { afterEach, describe, expect, it } from 'vitest';

import { MAX_TAINT_HOPS } from '../../../../src/modules/sast/taint.js';
import { runSastOnText } from '../../../../src/modules/sast/engine.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_TAINT_V2';

async function cmdi(code: string): Promise<boolean> {
  const hits = await runSastOnText('fixture.js', code);
  return hits.some((f) => f.ruleId === 'SAST-CMDI-001');
}

describe('Phase 40 taint v2', () => {
  afterEach(() => {
    delete process.env[FLAG];
  });

  it('keeps depth 5', () => {
    expect(MAX_TAINT_HOPS).toBe(5);
  });

  it('follows array callbacks only when the flag is on', async () => {
    const code = `
      const { exec } = require('child_process');
      function handler(req, res) {
        const items = req.query.cmds;
        items.forEach((item) => { exec(item); });
      }
    `;
    expect(await cmdi(code)).toBe(false);
    process.env[FLAG] = '1';
    expect(await cmdi(code)).toBe(true);
  });

  it('does not taint a callback over a literal list', async () => {
    process.env[FLAG] = '1';
    const code = `
      const { exec } = require('child_process');
      function handler(req, res) {
        const items = ['ls'];
        items.forEach((item) => { exec(item); });
      }
    `;
    expect(await cmdi(code)).toBe(false);
  });

  it('follows Object.assign and spread only from a tainted value', async () => {
    process.env[FLAG] = '1';
    const tainted = `
      const { exec } = require('child_process');
      function handler(req, res) {
        const copy = Object.assign({}, req.body);
        exec(copy.cmd);
      }
    `;
    const clean = `
      const { exec } = require('child_process');
      function handler(req, res) {
        const copy = Object.assign({}, { cmd: 'ls' });
        exec(copy.cmd);
      }
    `;
    expect(await cmdi(tainted)).toBe(true);
    expect(await cmdi(clean)).toBe(false);
  });

  it('follows call() into a function parameter', async () => {
    process.env[FLAG] = '1';
    const code = `
      const { exec } = require('child_process');
      function run(cmd) { exec(cmd); }
      function handler(req, res) { run.call(null, req.query.cmd); }
    `;
    expect(await cmdi(code)).toBe(true);
  });

  it('does not follow call() of a literal', async () => {
    process.env[FLAG] = '1';
    const code = `
      const { exec } = require('child_process');
      function run(cmd) { exec(cmd); }
      function handler(req, res) { run.call(null, 'ls'); }
    `;
    expect(await cmdi(code)).toBe(false);
  });

  it('follows a tainted this field across methods', async () => {
    process.env[FLAG] = '1';
    const code = `
      const { exec } = require('child_process');
      class Job {
        set(req) { this.cmd = req.body.cmd; }
        run() { exec(this.cmd); }
      }
    `;
    expect(await cmdi(code)).toBe(true);
  });

  it('does not treat an assigned literal this field as tainted', async () => {
    process.env[FLAG] = '1';
    const code = `
      const { exec } = require('child_process');
      class Job {
        set() { this.cmd = 'ls'; }
        run() { exec(this.cmd); }
      }
    `;
    expect(await cmdi(code)).toBe(false);
  });

  it('follows a closure over a tainted binding', async () => {
    process.env[FLAG] = '1';
    const code = `
      const { exec } = require('child_process');
      function handler(req, res) {
        const cmd = req.query.cmd;
        function inner() { exec(cmd); }
        inner();
      }
    `;
    expect(await cmdi(code)).toBe(true);
  });

  it('follows promise then, apply, and a tainted spread', async () => {
    process.env[FLAG] = '1';
    const thenCode = `
      const { exec } = require('child_process');
      function handler(req, res) {
        Promise.resolve(req.query.cmd).then((cmd) => exec(cmd));
      }
    `;
    const applyCode = `
      const { exec } = require('child_process');
      function run(cmd) { exec(cmd); }
      function handler(req, res) { run.apply(null, req.query.cmds); }
    `;
    const spreadCode = `
      const { exec } = require('child_process');
      function handler(req, res) {
        const parts = [...req.query.cmds];
        exec(parts[0]);
      }
    `;
    expect(await cmdi(thenCode)).toBe(true);
    expect(await cmdi(applyCode)).toBe(true);
    expect(await cmdi(spreadCode)).toBe(true);
  });

  it('finishes a small file inside the time budget', async () => {
    process.env[FLAG] = '1';
    const started = Date.now();
    await cmdi(`
      const { exec } = require('child_process');
      function handler(req, res) {
        req.query.cmds.forEach((item) => exec(item));
      }
    `);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
