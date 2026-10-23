import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, startTelemetry } from '../../../src/runtime/exp/p393.js';

describe('phase 393 local telemetry', () => {
  it('does not import or send when the endpoint is unset', () => {
    process.env[FLAG] = '1';
    let imported = false;
    let sent = false;
    const started = startTelemetry({}, () => {
      imported = true;
    }, () => {
      sent = true;
    }, { hook: 'sql', labels: ['request'] });
    expect(started.imported).toBe(false);
    expect(imported).toBe(false);
    expect(sent).toBe(false);
  });

  it('sends one event without a body or a secret field', () => {
    process.env[FLAG] = '1';
    const endpoint = 'http://127.0.0.1:9/v1/traces';
    let payload = '';
    const started = startTelemetry({ endpoint }, () => undefined, (_endpoint, event) => {
      payload = JSON.stringify(event);
    }, { hook: 'sql', labels: ['request'] });
    expect(started.imported).toBe(true);
    expect(started.startup[0]).toContain(endpoint);
    expect(payload).not.toContain('body');
    expect(payload).not.toContain('secret');
  });

  it('has no host literal of its own', () => {
    expect(enabled()).toBe(false);
    const source = readFileSync(new URL('../../../src/runtime/exp/p393.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/https?:\/\/[a-z0-9.-]+/i);
    expect(source).not.toContain('src/modules');
  });
});
