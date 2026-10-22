import { describe, expect, it } from 'vitest';

import { enabled, FLAG, FsError, uploadHook, uploadStatic } from '../../../src/runtime/exp/p398.js';

describe('phase 398 uploads', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(uploadStatic('path.join(uploadDir, name)')).toEqual([]);
    expect(uploadHook('../a', 'text/html').reject).toBe(false);
  });

  it('reports a joined original name and a request content type', () => {
    process.env[FLAG] = '1';
    const path = uploadStatic('path.join(uploadDir, req.file.originalname)');
    expect(path.some((row) => row.ruleId === 'SAST-PATH-001')).toBe(true);
    const typed = uploadStatic("res.set('content-type', 'text/html')");
    expect(typed.some((row) => row.ruleId === 'SAST-UPLOAD-TYPE-001')).toBe(true);
  });

  it('does not report a forced octet-stream and rejects traversal', () => {
    process.env[FLAG] = '1';
    expect(uploadStatic("res.type('application/octet-stream')")).toEqual([]);
    expect(uploadHook('../secret', 'application/octet-stream').reject).toBe(true);
    expect(uploadHook('photo.png', 'image/svg+xml', ['image/svg+xml']).reject).toBe(false);
    expect(() => uploadHook('a', 'text/html', ['text/html'])).toThrow(FsError);
  });
});
