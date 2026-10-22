import { describe, expect, it } from 'vitest';

import { enabled, FLAG, templateFinding, templateRuntime } from '../../../src/runtime/exp/p389.js';

describe('phase 389 template source', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(templateFinding('ejs.render', 'request')).toBeNull();
  });

  it('reports ejs.render of a request template and not renderFile', () => {
    process.env[FLAG] = '1';
    const finding = templateFinding('ejs.render', 'request');
    expect(finding?.ruleId).toBe('SAST-SSTI-001');
    expect(finding?.argumentIndex).toBe(0);
    expect(templateFinding('ejs.renderFile', 'request')).toBeNull();
  });

  it('emits a runtime event only for a request-labeled template string', () => {
    process.env[FLAG] = '1';
    expect(templateRuntime('ejs.render', true).event).toBe(true);
    expect(templateRuntime('ejs.renderFile', true).event).toBe(false);
  });
});
