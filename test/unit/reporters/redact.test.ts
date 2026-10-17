import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { renderGithubAnnotations, renderGitlabCodeQuality, renderJunitReport } from '../../../src/reporters/ci.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';
import { renderJsonReport } from '../../../src/reporters/json.js';
import { renderMarkdownReport } from '../../../src/reporters/markdown.js';
import { renderSarifReport } from '../../../src/reporters/sarif.js';

const SECRET = 'AKIAIOSFODNN7EXAMPLE';

const finding: Finding = {
  id: makeFindingId('SECRET-AWS-001', '.env', SECRET),
  ruleId: 'SECRET-AWS-001',
  module: 'secrets',
  title: `AWS key ${SECRET}`,
  severity: 'critical',
  confidence: 'high',
  file: '.env',
  line: 2,
  snippet: SECRET,
  message: `Found ${SECRET} in the file.`,
  remediation: `Rotate ${SECRET}.`,
};

function result(): ScanResult {
  return {
    findings: [finding],
    summary: summarize([finding]),
    metadata: {
      version: '0.3.0',
      startedAt: '2026-10-17T00:00:00.000Z',
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['secrets'],
      modulesRun: ['secrets'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

describe('secret redaction in every report format', () => {
  const outputs = [
    renderConsoleReport(result()),
    renderJsonReport(result()),
    renderSarifReport(result()),
    renderMarkdownReport(result()),
    renderHtmlReport(result()),
    renderGithubAnnotations(result()),
    renderJunitReport(result()),
    renderGitlabCodeQuality(result()),
  ];

  it.each(outputs)('masks the token %#', (output) => {
    expect(output).not.toContain(SECRET);
    expect(output).toContain('AKIA****');
  });
});
