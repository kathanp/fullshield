import { describe, expect, it } from 'vitest';

import { runConfigAstChecks } from '../../../../src/modules/config/astChecks.js';

describe('phase 26b — config bench misses (stable)', () => {
  it('flags commented-out helmet on the comment line (NodeGoat server.js:10)', async () => {
    const src = `"use strict";\nconst express = require("express");\n// const helmet = require("helmet");\nconst app = express();\n`;
    const findings = await runConfigAstChecks('server.js', src);
    const helmet = findings.filter((f) => f.ruleId === 'CONFIG-HELMET-001');
    expect(helmet.some((f) => f.line === 3)).toBe(true);
  });

  it('does not flag helmet comment when helmet() is actually used', async () => {
    const src = `const express = require('express');\nconst helmet = require('helmet');\nconst app = express();\napp.use(helmet());\n`;
    const findings = await runConfigAstChecks('server.js', src);
    expect(findings.filter((f) => f.ruleId === 'CONFIG-HELMET-001')).toEqual([]);
  });

  it('flags serveIndex directory listing (Juice Shop /ftp and /support/logs)', async () => {
    const src = `import serveIndex from 'serve-index';\napp.use('/ftp', serveIndex('ftp', { icons: true }));\napp.use('/support/logs', serveIndex('logs', { icons: true }));\n`;
    const findings = await runConfigAstChecks('server.ts', src);
    const hits = findings.filter((f) => f.ruleId === 'CONFIG-DIRLIST-001');
    expect(hits.length).toBeGreaterThanOrEqual(2);
    expect(hits.some((f) => f.line === 2)).toBe(true);
    expect(hits.some((f) => f.line === 3)).toBe(true);
  });

  it('does not flag express.static without serveIndex', async () => {
    const src = `app.use('/public', express.static('public'));\n`;
    const findings = await runConfigAstChecks('server.ts', src);
    expect(findings.filter((f) => f.ruleId === 'CONFIG-DIRLIST-001')).toEqual([]);
  });
});
