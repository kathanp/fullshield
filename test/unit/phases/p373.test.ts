import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, sriTags } from '../../../src/phases/p373.js';

describe('phase 373 SRI tags', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(sriTags('a.html', '<script src="https://cdn.example.invalid/a.js"></script>', 'html')).toEqual([]);
  });

  it('reports a cross-origin script without integrity', () => {
    process.env[FLAG] = '1';
    const findings = sriTags('a.html', '<script src="https://cdn.example.invalid/a.js" nonce="n"></script>', 'html');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('CONFIG-SRI-001');
    expect(findings[0]?.severity).toBe('low');
  });

  it('does not report this id when integrity is present', () => {
    process.env[FLAG] = '1';
    const html = '<script src="https://cdn.example.invalid/a.js" integrity="sha512-aaaa"></script>';
    expect(sriTags('a.html', html, 'html')).toEqual([]);
  });

  it('does not report a relative script', () => {
    process.env[FLAG] = '1';
    expect(sriTags('a.html', '<script src="/static/app.js"></script>', 'html')).toEqual([]);
  });

  it('does not open a socket', () => {
    const source = readFileSync(new URL('../../../src/phases/p373.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:net');
  });

  it('reports a stylesheet link and skips comments, icons, and tags with no url', () => {
    process.env[FLAG] = '1';
    const html = [
      '<!-- <script src="https://cdn.example.invalid/hidden.js"></script> -->',
      '<link rel="stylesheet" href="https://cdn.example.invalid/a.css">',
      '<link rel="icon" href="https://cdn.example.invalid/a.ico">',
      '<script nonce="n"></script>',
      '<script src="http://cdn.example.invalid/b.js"></script>',
      '<script src="https://["></script>',
    ].join('\n');
    const findings = sriTags('a.html', html, 'html');
    expect(findings.map((row) => row.url)).toEqual([
      'https://cdn.example.invalid/a.css',
      'http://cdn.example.invalid/b.js',
    ]);
    expect(sriTags('a.html', '<!-- <script src="https://cdn.example.invalid/open.js"></script>', 'html')).toEqual([]);
    expect(sriTags('a.html', '<script src="https://cdn.example.invalid/a.js"></script>', 'html', ['cdn.example.invalid'])).toEqual([]);
    delete process.env[FLAG];
  });

  it('reports jsx script and link tags and ignores the rest', () => {
    process.env[FLAG] = '1';
    const source = [
      'const view = (',
      '  <div>',
      '    <script src="https://cdn.example.invalid/a.js" />',
      '    <script src="https://cdn.example.invalid/safe.js" integrity="sha384-aaaa" />',
      '    <script integrity />',
      '    <script src={remote} />',
      '    <link rel="stylesheet" href="https://cdn.example.invalid/a.css" />',
      '    <link href="https://cdn.example.invalid/skip.css" />',
      '    <ns.script src="https://cdn.example.invalid/member.js" />',
      '    <script {...props} src="http://cdn.example.invalid/spread.js" />',
      '  </div>',
      ');',
    ].join('\n');
    const findings = sriTags('a.jsx', source, 'jsx');
    expect(findings.map((row) => row.url).sort()).toEqual([
      'http://cdn.example.invalid/spread.js',
      'https://cdn.example.invalid/a.css',
      'https://cdn.example.invalid/a.js',
    ]);
    expect(sriTags('a.jsx', 'const view = <script src="https://cdn.example.invalid/a.js" />;', 'jsx', ['cdn.example.invalid'])).toEqual([]);
    expect(sriTags('a.jsx', 'const view = <script src="https://[" />;', 'jsx')).toEqual([]);
    expect(sriTags('a.jsx', 'const view = <', 'jsx')).toEqual([]);
    delete process.env[FLAG];
  });
});
