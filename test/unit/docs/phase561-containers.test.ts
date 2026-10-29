import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = join(import.meta.dirname, '../../..');

describe('phase 561 container non-goal', () => {
  it('says FullShield does not scan containers and points Trivy SARIF at ingest', async () => {
    const readme = await readFile(join(root, 'README.md'), 'utf8');
    expect(readme).toMatch(/does \*\*not\*\* scan container images or OS packages/i);
    expect(readme).toMatch(/Trivy SARIF/);
    expect(readme).toMatch(/fullshield ingest/);
    expect(readme).not.toMatch(/FullShield scans container images/);
  });
});
