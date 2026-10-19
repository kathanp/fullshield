import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const ALLOWED = new Set([
  'docs.aws.amazon.com',
  'docs.github.com',
  'docs.stripe.com',
  'api.slack.com',
  'cloud.google.com',
  'platform.openai.com',
  'docs.anthropic.com',
  'www.postgresql.org',
  'www.rfc-editor.org',
  'cheatsheetseries.owasp.org',
]);

describe('phase 69 secret rotation playbooks', () => {
  it('gives every secrets rule a Rotate section whose links stay on provider docs', () => {
    const dir = join(import.meta.dirname, '../../../rules');
    const files = readdirSync(dir).filter((name) => name.startsWith('SECRET-') && name.endsWith('.md'));
    expect(files.length).toBeGreaterThanOrEqual(12);
    for (const file of files) {
      const text = readFileSync(join(dir, file), 'utf8');
      expect(text, file).toContain('## Rotate');
      expect(text, file).toMatch(/does not un-leak/i);
      const urls = [...text.matchAll(/https:\/\/([^/\s)]+)/g)].map((match) => match[1]);
      expect(urls.length, file).toBeGreaterThan(0);
      for (const host of urls) expect(ALLOWED.has(host ?? ''), `${file} ${host}`).toBe(true);
    }
  });
});
