import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = join(import.meta.dirname, '../../..');

describe('phase 59 github action', () => {
  it('uploads SARIF, caches the baseline, pins fullshield, and names no telemetry endpoint', () => {
    const action = readFileSync(join(root, 'templates/action/action.yml'), 'utf8');
    const workflow = readFileSync(join(root, 'templates/github-workflow.yml'), 'utf8');
    for (const text of [action, workflow]) {
      expect(text).toMatch(/^name:/);
      expect(text).toContain('upload-sarif');
      expect(text).toContain('fullshield.sarif');
      expect(text).toContain('.fullshield-baseline.json');
      expect(text).toContain('fullshield@');
      expect(text).not.toMatch(/pull-request comment|phone home|telemetry|analytics/i);
      expect(text).not.toMatch(/https?:\/\/(?!github\.com|actions\/)/);
    }
    expect(action).toContain("default: '0.4.0'");
    expect(workflow).toContain('fullshield@0.4.0');
  });
});
