import { afterEach, describe, expect, it } from 'vitest';

import { dockerFindings, enabled, FLAG } from '../../../src/phases/p337.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth', source: 'https://example.invalid/grammar', prefix: 'fsyn_', alphabet: 'A-Za-z0-9', length: 16, notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 337 dockerfile args', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(dockerFindings('Dockerfile', `ARG SECRET=${TOKEN}`, formats).findings).toEqual([]);
  });

  it('rates an intermediate ARG as info and a copied ARG as high', () => {
    process.env[FLAG] = '1';
    const dead = `FROM node:20 AS build\nARG SECRET=${TOKEN}\nFROM node:20\n`;
    const copied = `FROM node:20 AS build\nARG SECRET=${TOKEN}\nFROM node:20\nCOPY --from=build /app /app\n`;
    expect(dockerFindings('Dockerfile', dead, formats).findings[0]?.severity).toBe('info');
    expect(dockerFindings('Dockerfile', copied, formats).findings[0]?.severity).toBe('high');
  });

  it('ignores a BuildKit secret mount and rates RUN echo as high', () => {
    process.env[FLAG] = '1';
    expect(dockerFindings('Dockerfile', 'RUN --mount=type=secret,id=npmrc npm ci\n', formats).findings).toEqual([]);
    const echoed = `FROM node:20\nARG SECRET=${TOKEN}\nRUN echo $SECRET\n`;
    expect(dockerFindings('Dockerfile', echoed, formats).findings[0]?.severity).toBe('high');
  });

  it('treats a missing stage as incomplete and ignores an ARG that is not a secret', () => {
    process.env[FLAG] = '1';
    expect(dockerFindings('Dockerfile', 'RUN echo hello\n', formats)).toEqual({ findings: [], events: [] });
    const plain = dockerFindings('Dockerfile', 'FROM scratch\nARG NAME\nENV MODE=dev\n', formats);
    expect(plain.findings).toEqual([]);
    const missing = dockerFindings('Dockerfile', `FROM node:20 AS final\nARG SECRET=${TOKEN}\nCOPY --from=ghost /src /src\nRUN --mount=type=secret,id=npmrc npm ci\n`, formats);
    expect(missing.findings[0]?.severity).toBe('high');
    expect(missing.events.some((event) => event.detail === 'stage graph incomplete')).toBe(true);
    const cycle = `FROM node:20 AS one\nARG SECRET=${TOKEN}\nCOPY --from=two /a /a\nFROM node:20 AS two\nCOPY --from=one /b /b\n`;
    expect(dockerFindings('Dockerfile', cycle, formats).findings[0]?.witness).toBe('final');
    expect(dockerFindings('Dockerfile', `FROM node:20\nARG SECRET=${TOKEN}\nRUN echo $SECRET\n`, formats).findings[0]?.witness).toBe('echo');
  });
});
