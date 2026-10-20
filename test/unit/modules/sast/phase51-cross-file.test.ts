import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const root = join(import.meta.dirname, '../../../fixtures');

describe('phase 51 cross-file returns', () => {
  it('follows a SQL string and a Mongo filter returned from another file, not a literal', async () => {
    const result = await scan({ cwd: join(root, 'cross-file-app'), modules: ['sast'], offline: true });
    const sql = result.findings.filter((finding) => finding.ruleId === 'SAST-SQLI-001');
    const nosql = result.findings.filter((finding) => finding.ruleId === 'SAST-NOSQLI-001');
    expect(sql.some((finding) => finding.file === 'src/sql-app.js' && finding.trace?.some((step) => step.file === 'src/sql-lib.js'))).toBe(
      true,
    );
    expect(sql.some((finding) => finding.snippet?.includes('literal'))).toBe(false);
    expect(nosql.some((finding) => finding.file === 'src/nosql-app.js' && finding.trace?.some((step) => step.file === 'src/nosql-lib.js'))).toBe(
      true,
    );
  });
});
