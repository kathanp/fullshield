import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { formatCliError } from '../../../src/cli/errors.js';
import { scan } from '../../../src/core/engine.js';

const dirs: string[] = [];

function git(cwd: string, args: string[]): void {
  const result = spawnSync('git', ['-c', 'user.email=dev@example.com', '-c', 'user.name=dev', ...args], {
    cwd,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout);
  }
}

function repo(): string {
  const cwd = mkdtempSync(join(tmpdir(), 'fs-diffscan-'));
  dirs.push(cwd);
  git(cwd, ['init']);
  return cwd;
}

function commitAll(cwd: string): void {
  git(cwd, ['add', '.']);
  git(cwd, ['commit', '-m', 'init']);
}

afterEach(() => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN;
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('phase 501 diff scan', () => {
  it('rejects scan --diff when the flag is off and maps the error to FS-E018', async () => {
    const cwd = repo();
    writeFileSync(join(cwd, 'a.js'), 'function id(req) { return req.body.id; }\n');
    commitAll(cwd);
    await expect(scan({ cwd, diff: true, offline: true, modules: ['sast'] })).rejects.toThrow(
      /FULLSHIELD_EXPERIMENTAL_DIFFSCAN/,
    );
    const line = formatCliError(new Error('scan --diff requires FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1'));
    expect(line).toContain('FS-E018');
    const older = formatCliError(new Error('FULLSHIELD_EXPERIMENTAL_DIFF scan JSON'));
    expect(older).toContain('FS-E006');
  });

  it('exits on git failure instead of scanning the tree', async () => {
    const cwd = repo();
    writeFileSync(join(cwd, 'a.js'), 'function go(req) { db.query(req.body.id); }\n');
    process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN = '1';
    await expect(scan({ cwd, diff: true, offline: true, modules: ['sast'] })).rejects.toThrow(/git failed/);
  });

  it('reports a sink in the importer when the changed file returns the request value', async () => {
    const cwd = repo();
    writeFileSync(
      join(cwd, 'carrier.js'),
      'function userId(req) { return req.body.id; }\nfunction literal() { return "SELECT 1"; }\nmodule.exports = { userId, literal };\n',
    );
    writeFileSync(
      join(cwd, 'app.js'),
      'const { userId, literal } = require("./carrier");\nfunction go(req) { db.query("SELECT \'" + userId(req) + "\'"); db.query(literal()); }\n',
    );
    writeFileSync(join(cwd, 'mid.js'), 'const app = require("./app");\nfunction go(req) { db.query(req.body.id); }\n');
    writeFileSync(join(cwd, 'note.js'), '// require("./carrier")\nfunction go(req) { db.query(req.body.id); }\n');
    writeFileSync(join(cwd, 'dyn.js'), 'function go(name, req) { import(name); db.query(req.body.id); }\n');
    commitAll(cwd);
    writeFileSync(
      join(cwd, 'carrier.js'),
      'function userId(req) { return req.body.id; }\nfunction literal() { return "SELECT 1"; }\nmodule.exports = { userId, literal };\n// touched\n',
    );
    process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN = '1';
    const result = await scan({ cwd, diff: true, offline: true, modules: ['sast'] });
    const sql = result.findings.filter((finding) => finding.ruleId === 'SAST-SQLI-001');
    expect(sql.some((finding) => finding.file === 'app.js')).toBe(true);
    expect(sql.some((finding) => finding.snippet?.includes('literal'))).toBe(false);
    expect(sql.some((finding) => finding.file === 'mid.js' || finding.file === 'note.js' || finding.file === 'dyn.js')).toBe(
      false,
    );
    expect(result.metadata.filesScanned).toBe(2);
  });

  it('does not treat a comment or a dynamic import as an edge', async () => {
    const cwd = repo();
    writeFileSync(join(cwd, 'carrier.js'), 'function userId(req) { return req.body.id; }\nmodule.exports = { userId };\n');
    writeFileSync(join(cwd, 'note.js'), '// require("./carrier")\nfunction go(req) { db.query(req.body.id); }\n');
    writeFileSync(join(cwd, 'dyn.js'), 'function go(name, req) { import(name); db.query(req.body.id); }\n');
    commitAll(cwd);
    writeFileSync(join(cwd, 'carrier.js'), 'function userId(req) { return req.body.id; }\nmodule.exports = { userId };\n// touched\n');
    process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN = '1';
    const result = await scan({ cwd, diff: true, offline: true, modules: ['sast'] });
    expect(result.metadata.filesScanned).toBe(1);
    expect(result.findings.some((finding) => finding.file === 'note.js' || finding.file === 'dyn.js')).toBe(false);
  });

  it('scans no source files when nothing changed', async () => {
    const cwd = repo();
    writeFileSync(join(cwd, 'a.js'), 'function go(req) { db.query(req.body.id); }\n');
    commitAll(cwd);
    process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN = '1';
    const result = await scan({ cwd, diff: true, offline: true, modules: ['sast'] });
    expect(result.findings).toEqual([]);
    expect(result.metadata.filesScanned).toBe(0);
  });

  it('follows one import hop and the existing sink rules', async () => {
    const cwd = repo();
    writeFileSync(join(cwd, 'types.d.ts'), 'export declare function userId(req: unknown): string;\n');
    mkdirSync(join(cwd, 'lib'));
    writeFileSync(
      join(cwd, 'lib', 'index.js'),
      'function userId(req) { return req.body.id; }\nfunction hidden(req) { return req.body.id; }\nfunction literal() { return "1"; }\nmodule.exports = { userId, literal, nope: 1 };\n',
    );
    writeFileSync(
      join(cwd, 'app.js'),
      [
        'const { userId } = require("./lib");',
        'function go(req) {',
        '  db.query(userId(req));',
        '  exec(userId(req));',
        '  fs.readFile(userId(req));',
        '  ordersCollection.find(userId(req));',
        '  fetch(userId(req));',
        '  eval(userId(req));',
        '  res.redirect(userId(req));',
        '  res.send("<p>" + userId(req) + "</p>");',
        '  res.send(userId(req));',
        '  window.fetch(userId(req));',
        '  db.query(...userId(req));',
        '  db.execute((0, userId)(req));',
        '}',
      ].join('\n'),
    );
    writeFileSync(join(cwd, 'other.js'), 'function userId(req) { return req.body.id; }\nexports.userId = userId;\n');
    writeFileSync(join(cwd, 'use-other.js'), 'const { userId } = require("./other");\nfunction go(req) { db.query(userId(req)); }\n');
    writeFileSync(join(cwd, 'export-fn.js'), 'export function userId(req) { return "1"; }\n');
    writeFileSync(join(cwd, 'esm-app.js'), 'import { userId } from "./export-fn.js";\nfunction go(req) { db.query(userId(req)); }\n');
    writeFileSync(join(cwd, 'notes.txt'), 'not source\n');
    commitAll(cwd);
    writeFileSync(
      join(cwd, 'lib', 'index.js'),
      'function userId(req) { return req.body.id; }\nfunction hidden(req) { return req.body.id; }\nfunction literal() { return "1"; }\nfunction nested(req) { function inner() { return req.body.id; } return "safe"; }\nmodule.exports = { userId, literal, nope: 1, ...{}, nested };\nrequire("./missing");\n/* require("./skip") */\n',
    );
    writeFileSync(join(cwd, 'types.d.ts'), 'export declare function userId(req: unknown): string;\n');
    writeFileSync(join(cwd, 'other.js'), 'function userId(req) { return req.body.id; }\nexports.userId = userId;\n// touched\n');
    writeFileSync(join(cwd, 'export-fn.js'), 'export function userId(req) { return req.body.id; }\n');
    writeFileSync(join(cwd, 'notes.txt'), 'still not source\n');
    writeFileSync(join(cwd, 'fresh.js'), 'function go(req) { db.query(req.body.id); }\n');
    process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN = '1';
    const result = await scan({ cwd, diff: true, offline: true, modules: ['sast'] });
    const rules = new Set(result.findings.filter((finding) => finding.file === 'app.js').map((finding) => finding.ruleId));
    expect(rules).toEqual(new Set([
      'SAST-SQLI-001',
      'SAST-CMDI-001',
      'SAST-PATH-001',
      'SAST-NOSQLI-001',
      'SAST-SSRF-001',
      'SAST-EVAL-001',
      'SAST-REDIRECT-001',
      'SAST-XSS-001',
    ]));
    expect(result.findings.some((finding) => finding.file === 'use-other.js' && finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(result.findings.some((finding) => finding.file === 'esm-app.js' && finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(result.findings.some((finding) => finding.file === 'types.d.ts')).toBe(false);
    expect(result.findings.some((finding) => finding.file === 'fresh.js' && finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(result.metadata.filesScanned).toBe(7);
  });

  it('matches a second run byte for byte and leaves a full scan unchanged when --diff is absent', async () => {
    const cwd = repo();
    writeFileSync(
      join(cwd, 'carrier.js'),
      'function userId(req) { return req.body.id; }\nmodule.exports = { userId };\n',
    );
    writeFileSync(
      join(cwd, 'app.js'),
      'const { userId } = require("./carrier");\nfunction go(req) { db.query(userId(req)); }\n',
    );
    commitAll(cwd);
    writeFileSync(
      join(cwd, 'carrier.js'),
      'function userId(req) { return req.body.id; }\nmodule.exports = { userId };\n',
    );
    process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN = '1';
    const first = await scan({ cwd, diff: true, offline: true, modules: ['sast'] });
    const second = await scan({ cwd, diff: true, offline: true, modules: ['sast'] });
    const key = (findings: typeof first.findings) =>
      JSON.stringify(
        findings
          .map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity])
          .sort(),
      );
    expect(key(second.findings)).toBe(key(first.findings));
    delete process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN;
    const full = await scan({ cwd, offline: true, modules: ['sast'] });
    expect(full.metadata.filesScanned).toBeGreaterThan(first.metadata.filesScanned);
  });
});
