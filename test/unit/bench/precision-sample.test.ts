import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

describe('precision review tooling', () => {
  it('ignores blank labels, counts unsure separately, and samples with a fixed seed', () => {
    const result = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { parseCsv, precisionFromRows } from './scripts/precision.mjs';
         import { mulberry32, sampleStratified } from './scripts/sample-findings.mjs';
         const records = parseCsv('ruleId,label\\nSAST-SQLI-001,TP\\nSAST-SQLI-001,FP\\nSAST-SQLI-001,unsure\\nDEPS-VULN-001,\\n');
         const { buckets, ignored } = precisionFromRows(records);
         const findings = [
           ...Array.from({ length: 10 }, (_, i) => ({ id: 'd' + i, module: 'deps' })),
           ...Array.from({ length: 4 }, (_, i) => ({ id: 's' + i, module: 'sast' })),
         ];
         const a = sampleStratified(findings, 6, mulberry32(20261016));
         const b = sampleStratified(findings, 6, mulberry32(20261016));
         console.log(JSON.stringify({
           ignored,
           rule: buckets.get('rule\\tSAST-SQLI-001'),
           same: a.map((row) => row.id).join(',') === b.map((row) => row.id).join(','),
           sast: a.filter((row) => row.module === 'sast').length,
           deps: a.filter((row) => row.module === 'deps').length,
           unlabeled: a.every((row) => row.label === undefined),
         }));`,
      ],
      { encoding: 'utf8' },
    );
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      ignored: 1,
      rule: { TP: 1, FP: 1, unsure: 1 },
      same: true,
      sast: 3,
      deps: 3,
      unlabeled: true,
    });
  });
});
