import { afterEach, describe, expect, it } from 'vitest';

import { callTool, enabled, FLAG, toolManifest, type WitnessRecord } from '../../../src/phases/p437.js';

afterEach(() => {
  delete process.env[FLAG];
});

const witness: WitnessRecord = { id: 'w1', source: 'src/a.js', sink: 'db.query', proof: { steps: 1 } };

const data = { routes: [{ method: 'GET', path: '/users' }], witnesses: [witness] };

describe('phase 437 MCP tools', () => {
  it('registers no tools when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(toolManifest()).toEqual({ tools: [] });
    expect(callTool('route_matrix', {}, data)).toEqual({ isError: true, code: 'FS-E', body: {} });
  });

  it('returns routes, a witness, and a dry-run fix', () => {
    process.env[FLAG] = '1';
    expect(toolManifest().tools.map((tool) => tool.name)).toEqual(['route_matrix', 'get_witness', 'proof_json', 'fix']);
    expect(callTool('route_matrix', {}, data)).toEqual({ isError: false, body: { routes: data.routes } });
    expect(callTool('get_witness', { id: 'w1' }, data)).toEqual({ isError: false, body: { witness } });
    expect(callTool('proof_json', { id: 'w1' }, data)).toEqual({ isError: false, body: { proof: witness.proof } });
    expect(callTool('fix', {}, data)).toEqual({ isError: false, body: { dryRun: true, applied: false } });
    expect(callTool('fix', { apply: true }, data)).toEqual({ isError: false, body: { dryRun: false, applied: true } });
  });

  it('rejects an unknown witness, a non-boolean apply, and an unknown tool', () => {
    process.env[FLAG] = '1';
    expect(callTool('get_witness', { id: 'missing' }, data)).toEqual({
      isError: true,
      code: 'unknown_id',
      body: { message: 'unknown witness missing' },
    });
    expect(callTool('fix', { apply: 'yes' }, data)).toEqual({ isError: false, body: { dryRun: true, applied: false } });
    expect(callTool('other', {}, data)).toEqual({ isError: true, code: 'unknown_tool', body: { message: 'other' } });
  });
});
