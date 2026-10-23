import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, writeHtml, type HtmlFinding } from '../../../src/phases/p434.js';

afterEach(() => {
  delete process.env[FLAG];
});

const finding: HtmlFinding = {
  title: 'say "hi" <b>',
  message: 'token AKIAIOSFODNN7EXAMPLE and s3cr3t',
  file: 'src/a.js',
  line: 2,
  secret: 's3cr3t',
};

describe('phase 434 offline HTML report', () => {
  it('errors with FS-E and writes nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(writeHtml([finding], 'report.html')).toEqual({ exitCode: 1, code: 'FS-E', wrote: false, html: null });
  });

  it('renders a static page with secrets and markup escaped', () => {
    process.env[FLAG] = '1';
    const result = writeHtml([finding], 'report.html');
    expect(result.exitCode).toBe(0);
    expect(result.wrote).toBe(true);
    const html = result.html ?? '';
    expect(html).toContain('say &quot;hi&quot; &lt;b&gt;');
    expect(html).toContain('AKIA****');
    expect(html).toContain('****');
    expect(html).toContain('src/a.js:2');
    expect(html).toContain('<style>');
    expect(html).not.toContain('<script');
    expect(html).not.toContain('<img');
    expect(html).not.toContain('<link');
    expect(html).not.toContain('http');
    expect(html).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(html).not.toContain('s3cr3t');
  });

  it('errors when no HTML path is given', () => {
    process.env[FLAG] = '1';
    expect(writeHtml([finding], undefined)).toEqual({ exitCode: 1, code: 'FS-E', wrote: false, html: null });
  });
});
