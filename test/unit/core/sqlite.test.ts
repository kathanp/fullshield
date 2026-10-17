import { describe, expect, it } from 'vitest';

import { nodeSqliteUnavailableMessage } from '../../../src/core/sqlite.js';

describe('node:sqlite availability', () => {
  it('names Node 22.13 in the history message', () => {
    expect(nodeSqliteUnavailableMessage('history')).toContain('requires Node 22.13+');
    expect(nodeSqliteUnavailableMessage('history')).toContain('node:sqlite');
  });
});
