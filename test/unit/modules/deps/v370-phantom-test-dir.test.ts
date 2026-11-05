import { describe, expect, it } from 'vitest';

import { dependencyShapeFindings } from '../../../../src/modules/deps/phantom.js';

describe('3.7.0 phantom imports under test/', () => {
  it('skips an undeclared import that exists only under test/ and still reports src/', () => {
    const findings = dependencyShapeFindings('{"name":"app","dependencies":{}}', [], [
      { file: 'test/security/profile-test.js', text: 'const chrome = require("chromedriver");\n' },
      { file: 'src/app.js', text: 'const missing = require("missing-pkg");\n' },
    ]);
    const ids = findings.filter((finding) => finding.ruleId === 'DEPS-PHANTOM-001').map((finding) => finding.snippet);
    expect(ids).not.toContain('chromedriver');
    expect(ids).toContain('missing-pkg');
  });
});
