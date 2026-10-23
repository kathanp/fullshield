import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, pathGuard } from '../../../src/phases/p409.js';

const join = 'function other() { return 1; }\npath.join(root, req.query.p)';
const upload = 'path.join(dir, req.file.originalname)';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 409', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(pathGuard(join, 'literal', 'multi').source).toBe(join);
  });

  it('inserts the separator check and basename only for a filename', () => {
    process.env[FLAG] = '1';
    const guarded = pathGuard(join, 'literal', 'multi');
    expect(guarded.refused).toBe(false);
    expect(guarded.source).toContain('path.sep');
    expect(guarded.source).toContain('function other() { return 1; }');
    expect(/\.startsWith\(base\)/.test(guarded.source)).toBe(false);
    expect(pathGuard(join, 'request', 'multi')).toMatchObject({ source: join, refused: true });
    expect(pathGuard(upload, 'literal', 'filename').source).toContain('path.basename(req.file.originalname)');
  });
});
