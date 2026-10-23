import { describe, expect, it } from 'vitest';

import { AUTO_APPLY_HOLES } from '../../../src/phases/p422.js';
import { collectFacts, FLAG, permissionApplyDisposition, suggestPermission } from '../../../src/phases/p464.js';

describe('phase 464', () => {
  it('allows literal reads and hosts without a child-process allow', () => {
    process.env[FLAG] = '1';
    const facts = collectFacts({ 'a.js': "const fs = require('fs');\nfs.readFile('./data');\nfetch('https://example.invalid/x');\n" });
    const suggestion = suggestPermission(facts);
    expect(suggestion?.command).toContain('--allow-fs-read=./data');
    expect(suggestion?.command).toContain('--allow-net=example.invalid');
    expect(suggestion?.command).not.toContain('--allow-child-process');
  });

  it('adds a child-process allow when the IR imports it', () => {
    process.env[FLAG] = '1';
    const facts = collectFacts({ 'a.js': "require('child_process');\n" });
    expect(suggestPermission(facts)?.command).toContain('--allow-child-process');
  });

  it('emits a gap and no star allow for a dynamic path', () => {
    process.env[FLAG] = '1';
    const facts = collectFacts({ 'a.js': 'fs.readFile(req.query.p);\n' });
    const suggestion = suggestPermission(facts);
    expect(suggestion?.gap).toContain('gap');
    expect(suggestion?.command ?? '').not.toContain('--allow-fs-read=*');
    expect(permissionApplyDisposition()).toBe('review');
    expect(AUTO_APPLY_HOLES).not.toContain('permission-model');
  });

  it('returns no suggestion when the flag is off', () => {
    const facts = collectFacts({ 'a.js': "fs.readFile('./data');\n" });
    expect(suggestPermission(facts)).toBeNull();
  });
});
