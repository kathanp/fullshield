import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

function project(files: Record<string, string>): string {
  const cwd = mkdtempSync(join(tmpdir(), 'fs-swig-'));
  for (const [rel, text] of Object.entries(files)) {
    const path = join(cwd, rel);
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, text);
  }
  return cwd;
}

async function xssLines(cwd: string): Promise<string[]> {
  const result = await scan({ cwd, modules: ['sast'], offline: true });
  return result.findings
    .filter((finding) => finding.ruleId === 'SAST-XSS-001')
    .map((finding) => `${finding.file?.split('/').pop()}:${finding.line}`);
}

describe('3.7.0 Swig numeric and session locals', () => {
  it('does not flag a Swig local that was checked with isNaN, and still flags an unchecked one', async () => {
    const checked = project({
      'src/app.js': `'use strict';
app.set('view engine', 'swig');
function update(req, res) {
  const preTax = eval(req.body.preTax);
  const bonus = eval(req.body.bonus);
  if (isNaN(preTax)) return res.render('contributions', { updateError: 'bad' });
  db.collection('c').findOne(req.params.id, (err, contrib) => {
    res.render('contributions', { ...contrib, bonus });
  });
}
`,
      'views/contributions.html': '{{ preTax }}\n{{ bonus }}\n',
    });
    const lines = await xssLines(checked);
    expect(lines).not.toContain('contributions.html:1');
    expect(lines).toContain('contributions.html:2');

    const raw = project({
      'src/app.js': `'use strict';
app.set('view engine', 'swig');
function update(req, res) {
  const preTax = eval(req.body.preTax);
  res.render('contributions', { preTax });
}
`,
      'views/contributions.html': '{{ preTax }}\n',
    });
    expect(await xssLines(raw)).toContain('contributions.html:1');
  });

  it('does not flag userId taken from the session, and still flags userId from the request', async () => {
    const session = project({
      'src/app.js': `'use strict';
app.set('view engine', 'swig');
function show(req, res) {
  const { userId } = req.session;
  res.render('allocations', { userId, name: req.query.name });
}
`,
      'views/allocations.html': '{{ userId }}\n{{ name }}\n',
    });
    const sessionLines = await xssLines(session);
    expect(sessionLines).not.toContain('allocations.html:1');
    expect(sessionLines).toContain('allocations.html:2');

    const params = project({
      'src/app.js': `'use strict';
app.set('view engine', 'swig');
function show(req, res) {
  const { userId } = req.params;
  res.render('allocations', { userId });
}
`,
      'views/allocations.html': '{{ userId }}\n',
    });
    expect(await xssLines(params)).toContain('allocations.html:1');
  });
});
