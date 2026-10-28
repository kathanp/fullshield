import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('Phase 551 Verify-in-60s docs', () => {
  it('README documents verify-in-60s for 2.3.0 with provenance and no new hosts', async () => {
    const readme = await readFile(join(root, 'README.md'), 'utf8');
    expect(readme).toMatch(/Verify in 60 seconds/i);
    expect(readme).toMatch(/npx fullshield@3\.\d+\.\d+ --version/);
    expect(readme).toContain('https://www.npmjs.com/package/fullshield');
    expect(readme).toMatch(/v3\.\d+\.\d+|tag\/v3\.\d+\.\d+/);
    expect(readme).toMatch(/provenance|OIDC/i);
    expect(readme).not.toMatch(/rekor\.sigstore\.dev|fulcio\.sigstore\.dev/i);
    expect(readme).toMatch(/GitHub Action/i);
    expect(readme).toMatch(/does not post (a )?pull-request comment/i);
  });
});
