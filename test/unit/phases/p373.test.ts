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
});
