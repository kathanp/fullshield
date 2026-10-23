import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, scanDocument } from '../../../src/phases/p334.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth',
  source: 'https://example.invalid/grammar',
  prefix: 'fsyn_',
  alphabet: 'A-Za-z0-9',
  length: 16,
  notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 334 structured secrets', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(scanDocument('a.yaml', `password: ${TOKEN}`, formats).findings).toEqual([]);
  });

  it('reports a token in a yaml comment and in a notebook output', () => {
    process.env[FLAG] = '1';
    expect(scanDocument('app.yaml', `# ${TOKEN}\nname: app`, formats).findings[0]?.witness).toBe('synth');
    const notebook = JSON.stringify({ cells: [{ cell_type: 'code', source: '1', outputs: [{ text: [TOKEN] }] }] });
    expect(scanDocument('note.ipynb', notebook, formats).findings).toHaveLength(1);
  });

  it('still reports a broken yaml file and records the event', () => {
    process.env[FLAG] = '1';
    const result = scanDocument('app.yaml', `\tbad: "\n${TOKEN}`, formats);
    expect(result.events[0]?.code).toBe(271);
    expect(result.findings[0]?.witness).toBe('synth');
  });

  it('reports changeme as info and not as a high-entropy secret', () => {
    process.env[FLAG] = '1';
    const result = scanDocument('app.yaml', 'password: changeme', formats);
    expect(result.findings.map((row) => row.ruleId)).toEqual(['SECRETS-PLACEHOLDER-001']);
    expect(result.findings[0]?.severity).toBe('info');
  });

  it('scans toml, notebooks, and plain text, and skips fixture paths', () => {
    process.env[FLAG] = '1';
    const random = 'abcdefghijklmnopqrstuvwxyz012345';
    expect(scanDocument('models/app.yaml', `password: ${TOKEN}`, formats).findings).toEqual([]);
    expect(scanDocument('src/models/app.yaml', `password: ${TOKEN}`, formats).findings).toEqual([]);
    expect(scanDocument('test/fixtures/app.yaml', `password: ${TOKEN}`, formats).findings).toEqual([]);
    expect(scanDocument('pkg\\models\\app.yaml', `password: ${TOKEN}`, formats).findings).toEqual([]);
    expect(scanDocument('app.toml', `password: ${TOKEN}`, formats).findings[0]?.ruleId).toBe('SECRETS-FORMAT-001');
    expect(scanDocument('app.ini', `password: ${random}`, formats).findings[0]?.ruleId).toBe('SECRETS-ENTROPY-001');
    expect(scanDocument('app.properties', 'password: abc\n# note\n: empty\nname: app', formats).findings).toEqual([]);
    expect(scanDocument('app.yaml', 'note: "ab\\\\cd"', formats).findings).toEqual([]);
    expect(scanDocument('app.yaml', 'password: "abc', formats).events[0]?.detail).toBe('structured parse failed');
    expect(scanDocument('readme.md', TOKEN, formats).findings[0]?.witness).toBe('synth');
    expect(scanDocument('readme.md', 'hello', formats).findings).toEqual([]);
    const notebook = JSON.stringify({
      cells: [
        null,
        { source: 'plain' },
        { source: ['left', TOKEN], outputs: 'no' },
        { outputs: [null, { text: 'right' }, { text: [TOKEN] }] },
      ],
    });
    expect(scanDocument('note.ipynb', notebook, formats).findings.length).toBeGreaterThan(0);
    expect(scanDocument('note.ipynb', '{', formats).events[0]?.detail).toBe('notebook parse failed');
    expect(scanDocument('note.ipynb', 'null', formats).events[0]?.detail).toBe('notebook parse failed');
    expect(scanDocument('note.ipynb', '{"cells":{}}', formats).events[0]?.detail).toBe('notebook parse failed');
  });
});
