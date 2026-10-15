import { describe, expect, it } from 'vitest';

import { scanTextForSecrets } from '../../../../src/modules/secrets/index.js';

describe('phase 26b — secrets bench misses (stable)', () => {
  it('flags a hardcoded express-session secret (DVNA keyboard cat)', () => {
    const src = `app.use(session({\n  secret: 'keyboard cat',\n  resave: true,\n  saveUninitialized: true,\n}));\n`;
    const hits = scanTextForSecrets('server.js', src).filter((f) => f.ruleId === 'SECRET-SESSION-001');
    expect(hits.length).toBe(1);
    expect(hits[0]?.line).toBe(2);
    expect(hits[0]?.snippet).toMatch(/keyb/);
    expect(hits[0]?.snippet).not.toContain('keyboard cat');
  });

  it('does not flag session secret loaded from the environment', () => {
    const src = `app.use(session({\n  secret: process.env.SESSION_SECRET,\n  resave: true,\n}));\n`;
    const hits = scanTextForSecrets('server.js', src).filter((f) => f.ruleId === 'SECRET-SESSION-001');
    expect(hits).toEqual([]);
  });
});
