import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';
import { renderMarkdownReport } from '../../../src/reporters/markdown.js';

function mkResult(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '0.1.0',
      startedAt: new Date().toISOString(),
      durationMs: 4,
      cwd: '/tmp/app',
      filesScanned: 2,
      modulesRequested: ['sast'],
      modulesRun: ['sast'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

const base: Finding = {
  id: makeFindingId('SAST-SQLI-001', 'src/a.js', 'q'),
  ruleId: 'SAST-SQLI-001',
  module: 'sast',
  title: 'SQL injection',
  severity: 'high',
  confidence: 'high',
  file: 'src/a.js',
  line: 3,
  message: 'concat',
  remediation: 'parameterize',
};

describe('markdown/html/console optional finding fields', () => {
  it('renders project location, reachability, trace, explanation, and empty reports', () => {
    const rich: Finding = {
      ...base,
      snippet: 'db.query(a+b)',
      reachability: 'reachable-via-dependency',
      dependencyPath: ['express', 'qs'],
      trace: [
        { file: 'src/a.js', line: 3, note: 'taint' },
        { file: 'src/b.js', note: 'sink' },
      ],
      explanation: 'why',
    };
    const noFile: Finding = {
      ...base,
      id: 'n',
      file: undefined,
      line: undefined,
      reachability: 'not-imported',
    };
    const fileOnly: Finding = { ...base, id: 'f', line: undefined, file: 'src/only.js' };

    const md = renderMarkdownReport(mkResult([rich, noFile, fileOnly]));
    expect(md).toContain('(project)');
    expect(md).toContain('src/only.js');
    expect(md).toContain('reachable-via-dependency');
    expect(md).toContain('express > qs');
    expect(md).toContain('src/a.js:3');
    expect(md).toContain('src/b.js');
    expect(md).toContain('why');

    expect(renderMarkdownReport(mkResult([]))).toContain('No findings.');

    const quoted: Finding = { ...base, id: 'q', title: 't " b', message: 'a & b < c' };
    const html = renderHtmlReport(mkResult([rich, noFile, fileOnly, quoted]));
    expect(html).toContain('(project)');
    expect(html).toContain('why');
    expect(html).toContain('&quot;');
    expect(html).toContain('&amp;');
    expect(html).toContain('&lt;');
    expect(renderHtmlReport(mkResult([]))).toContain('No findings.');

    const consoleOut = renderConsoleReport(mkResult([rich, noFile, fileOnly]));
    expect(consoleOut).toContain('db.query(a+b)');
    expect(consoleOut).toContain('reachability');
    expect(consoleOut).toContain('express > qs');
    expect(consoleOut).toContain('trace:');
    expect(consoleOut).toContain('explain: why');
    expect(consoleOut).toContain('(project)');
    expect(consoleOut).toContain('src/only.js');
    expect(consoleOut).toContain('finding(s)');
  });
});
