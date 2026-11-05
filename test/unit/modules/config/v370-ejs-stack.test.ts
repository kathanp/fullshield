import { join } from 'node:path';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { ejsStackFindings } from '../../../../src/modules/config/ejs-stack.js';

describe('3.7.0 EJS error.stack', () => {
  it('flags printed error.stack and err.stack, escaped or not', () => {
    const escaped = ejsStackFindings('views/error.ejs', '<pre><%= error.stack %></pre>\n');
    const raw = ejsStackFindings('views/fail.ejs', '<pre><%- err.stack %></pre>\n');
    expect(escaped.map((finding) => finding.ruleId)).toEqual(['CONFIG-ERRSTACK-001']);
    expect(escaped[0]?.line).toBe(1);
    expect(raw).toHaveLength(1);
  });

  it('stays quiet for a comment, a message, a test template, and a non-ejs file', () => {
    expect(ejsStackFindings('views/error.ejs', '<%# error.stack %>\n')).toEqual([]);
    expect(ejsStackFindings('views/error.ejs', '<%= error.message %>\n')).toEqual([]);
    expect(ejsStackFindings('test/error.ejs', '<%= error.stack %>\n')).toEqual([]);
    expect(ejsStackFindings('views/error.js', 'res.send(error.stack);\n')).toEqual([]);
  });

  it('reports the template from a config scan', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'fs-ejs-'));
    mkdirSync(join(cwd, 'views'));
    writeFileSync(join(cwd, 'views', 'error.ejs'), '<pre><%= error.stack %></pre>\n');
    writeFileSync(join(cwd, 'package.json'), '{"name":"ejs-app","version":"1.0.0"}\n');
    const result = await scan({ cwd, modules: ['config'], offline: true });
    const hit = result.findings.find((finding) => finding.file?.endsWith('error.ejs'));
    expect(hit?.ruleId).toBe('CONFIG-ERRSTACK-001');
  });
});
