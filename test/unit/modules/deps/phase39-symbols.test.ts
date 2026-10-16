import { describe, expect, it } from 'vitest';

import { makeFindingId, type Finding } from '../../../../src/core/finding.js';
import { applyPackageExports, applyTsPaths, packageSpec } from '../../../../src/core/module-resolve.js';
import { applyReachability } from '../../../../src/modules/deps/reachability.js';
import { affectedFunctionNames, sourceCallsAffectedSymbol } from '../../../../src/modules/deps/symbol-reachability.js';

function vulnFinding(severity: 'high' | 'critical' = 'high'): Finding {
  return {
    id: makeFindingId('DEPS-VULN-001', 'package.json', 'left-pad@1.0.0|GHSA-1'),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: 'Vulnerable dependency',
    severity,
    confidence: 'high',
    file: 'package.json',
    snippet: 'left-pad@1.0.0',
    message: 'left-pad@1.0.0 is affected by GHSA-1.',
    remediation: 'upgrade',
  };
}

const graph = {
  packages: [],
  edges: new Map<string, Set<string>>(),
  directProd: new Set<string>(['left-pad']),
  directDev: new Set<string>(),
  edgesKnown: true,
};

describe('Phase 39 symbol reachability', () => {
  it('keeps the import-level class when the advisory names no functions', () => {
    expect(affectedFunctionNames({ id: 'GHSA-1' })).toEqual([]);
    expect(affectedFunctionNames({ id: 'GHSA-1', affected: [{ ecosystem_specific: { affected_functions: 'merge' } }] })).toEqual(
      [],
    );
    const finding = vulnFinding();
    const next = applyReachability(
      [{ ...finding, reachability: undefined }],
      {
        productionUsage: new Map([['left-pad', { imported: true, called: false }]]),
        graph,
        sources: new Map([['app.js', "import { pad } from 'left-pad';\npad('x');\n"]]),
      },
      new Map(),
    );
    expect(next[0]?.reachability).toBe('imported-not-called');
    expect(next[0]?.severity).toBe('medium');
  });

  it('marks symbol-reachable for a named import, a require member, a subpath, and a namespace call', () => {
    expect(sourceCallsAffectedSymbol("import { merge } from 'lodash';\nmerge(a, b);\n", 'merge')).toBe(true);
    expect(sourceCallsAffectedSymbol("const _ = require('lodash');\n_.merge(a, b);\n", 'merge')).toBe(true);
    expect(sourceCallsAffectedSymbol("import merge from 'lodash/merge';\nmerge(a, b);\n", 'merge')).toBe(true);
    expect(sourceCallsAffectedSymbol("import * as _ from 'lodash';\n_.merge(a, b);\n", 'merge')).toBe(true);
    expect(sourceCallsAffectedSymbol("function merge() {}\nmerge();\n", 'merge')).toBe(false);
    const finding = vulnFinding();
    const next = applyReachability([finding], {
      productionUsage: new Map([['left-pad', { imported: true, called: false }]]),
      graph,
      sources: new Map([['app.js', "const { pad } = require('left-pad');\npad('x');\n"]]),
    }, new Map([[finding.id, ['pad']]]));
    expect(next[0]?.reachability).toBe('symbol-reachable');
    expect(next[0]?.severity).toBe('high');
  });

  it('marks symbol-not-called only when the advisory named a function and no source calls it', () => {
    const finding = vulnFinding();
    const next = applyReachability([finding], {
      productionUsage: new Map([['left-pad', { imported: true, called: true }]]),
      graph,
      sources: new Map([['app.js', "import { pad } from 'left-pad';\n"]]),
    }, new Map([[finding.id, ['pad']]]));
    expect(next[0]?.reachability).toBe('symbol-not-called');
    expect(next[0]?.severity).toBe('medium');
  });

  it('never downgrades DEPS-MALICIOUS-001 when symbol data is present', () => {
    const finding: Finding = {
      id: makeFindingId('DEPS-MALICIOUS-001', 'package-lock.json', 'evil@1.0.0'),
      ruleId: 'DEPS-MALICIOUS-001',
      module: 'deps',
      title: 'Malicious dependency',
      severity: 'critical',
      confidence: 'high',
      file: 'package-lock.json',
      snippet: 'evil@1.0.0',
      message: 'malicious',
      remediation: 'remove',
    };
    const next = applyReachability([finding], {
      productionUsage: new Map(),
      graph,
      sources: new Map([['app.js', 'const x = 1;\n']]),
    }, new Map([[finding.id, ['install']]]));
    expect(next[0]?.severity).toBe('critical');
    expect(next[0]?.ruleId).toBe('DEPS-MALICIOUS-001');
  });

  it('resolves package subpaths, tsconfig paths, and package exports', () => {
    expect(packageSpec('lodash/merge')).toEqual({ packageName: 'lodash', subpath: 'merge' });
    expect(packageSpec('@scope/pkg/sub')).toEqual({ packageName: '@scope/pkg', subpath: 'sub' });
    expect(applyTsPaths('@app/db', { '@app/*': ['src/*'] })).toBe('src/db');
    expect(applyPackageExports('merge', { './merge': './merge.js' })).toBe('./merge.js');
    expect(applyPackageExports('missing', { './merge': './merge.js' })).toBeUndefined();
  });
});
