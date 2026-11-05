import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function ids(code: string): Promise<string[]> {
  const findings = await runSastOnText('fixture.js', code);
  return findings.map((finding) => finding.ruleId);
}

const BAD = `export const isRedirectAllowed = (url) => {
  let allowed = false;
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl);
  }
  return allowed;
};
`;

describe('3.7.0 redirect allowlist includes()', () => {
  it('flags url.includes(allowedUrl) and leaves res.redirect on SAST-REDIRECT-001', async () => {
    const found = await ids(BAD);
    expect(found).toContain('SAST-REDIRECT-002');
    expect(found).not.toContain('SAST-REDIRECT-001');
  });

  it('stays quiet for startsWith and for a parsed URL compare', async () => {
    const prefix = `function isRedirectAllowed(url) {
      for (const allowedUrl of redirectAllowlist) {
        if (url.startsWith(allowedUrl)) return true;
      }
      return false;
    }
    `;
    const parsed = `function isRedirectAllowed(url) {
      const host = new URL(url).origin;
      return redirectAllowlist.some((allowedUrl) => host === allowedUrl);
    }
    `;
    expect(await ids(prefix)).not.toContain('SAST-REDIRECT-002');
    expect(await ids(parsed)).not.toContain('SAST-REDIRECT-002');
  });

  it('does not flag an exact allowlist membership check or an unrelated includes()', async () => {
    const exact = `function isRedirectAllowed(url) {
      return redirectAllowlist.includes(url);
    }
    `;
    const other = `function hasAdmin(name) { return name.includes('admin'); }\n`;
    expect(await ids(exact)).not.toContain('SAST-REDIRECT-002');
    expect(await ids(other)).not.toContain('SAST-REDIRECT-002');
  });
});
