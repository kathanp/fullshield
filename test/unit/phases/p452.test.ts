import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { COMPOSE_ENVFILE, COMPOSE_HOSTNET, COMPOSE_PORT, COMPOSE_PRIVILEGED, COMPOSE_SOCKET, FLAG, scanCompose } from '../../../src/phases/p452.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const token = `AKIA${'Z'.repeat(16)}`;

const dangerous = `services:
  web:
    build: .
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "3000:3000"
    environment:
      TOKEN: "\${TOKEN:-${token}}"
  redis:
    image: redis
    privileged: false
    network_mode: bridge
    ports:
      - "6379:6379"
`;

describe('phase 452', () => {
  it('reports each dangerous key and a defaulted secret', () => {
    process.env[FLAG] = '1';
    const findings = scanCompose('compose.yml', dangerous, 'web');
    expect(findings.some((row) => row.ruleId === COMPOSE_PRIVILEGED)).toBe(true);
    expect(findings.some((row) => row.ruleId === COMPOSE_HOSTNET)).toBe(true);
    expect(findings.some((row) => row.ruleId === COMPOSE_SOCKET && row.message.includes('web'))).toBe(true);
    expect(findings.some((row) => row.ruleId === COMPOSE_ENVFILE)).toBe(true);
    expect(findings.find((row) => row.ruleId === COMPOSE_PORT && row.message.includes('redis'))?.severity).toBe('low');
    expect(findings.find((row) => row.ruleId === COMPOSE_PORT && row.message.includes('web'))?.severity).toBe('medium');
  });

  it('does not treat a bare interpolation as a secret and ignores safe keys', () => {
    process.env[FLAG] = '1';
    const text = `services:\n  web:\n    image: demo\n    environment:\n      TOKEN: "\${TOKEN}"\n    privileged: false\n`;
    const findings = scanCompose('compose.yml', text, 'other');
    expect(findings.some((row) => row.ruleId === COMPOSE_ENVFILE)).toBe(false);
    expect(findings.some((row) => row.ruleId === COMPOSE_PRIVILEGED)).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'compose.yml', line: 1, message: 'kept' }];
    expect(scanCompose('compose.yml', dangerous, 'web', {}, baseline)).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p452.ts'), 'utf8');
    expect(src.includes('child_process')).toBe(false);
  });

  it('reads string volumes and env files, and ignores a document without services', () => {
    process.env[FLAG] = '1';
    try {
      const withFile = `services:\n  api:\n    image: shop-api\n    env_file: .env\n    volumes: /var/run/docker.sock:/var/run/docker.sock\n    ports: "3000:3000"\n    environment:\n      RAW: "AA\\n${token}"\n      SAFE: "\${FOO:-plain}"\n      NUM: 1\n`;
      const findings = scanCompose('compose.yml', withFile, 'shop-api', { '.env': `TOKEN=${token}\n` });
      expect(findings.some((row) => row.ruleId === COMPOSE_ENVFILE)).toBe(true);
      expect(findings.some((row) => row.ruleId === COMPOSE_SOCKET)).toBe(true);
      expect(findings.find((row) => row.ruleId === COMPOSE_PORT)?.severity).toBe('medium');
      expect(findings.find((row) => row.message.includes('secret literal'))?.line).toBe(1);
      expect(scanCompose('compose.yml', 'version: "3.8"\n', 'web')).toEqual([]);
      expect(scanCompose('compose.yml', 'services:\n  web: "nope"\n', 'web')).toEqual([]);
      const imageObj = 'services:\n  web:\n    image:\n      name: demo\n    ports:\n      - "1:1"\n';
      expect(scanCompose('compose.yml', imageObj, 'demo').find((row) => row.ruleId === COMPOSE_PORT)?.severity).toBe('low');
      const quietEnv = 'services:\n  web:\n    image: demo\n    env_file: missing.env\n';
      expect(scanCompose('compose.yml', quietEnv, 'other', {}).some((row) => row.ruleId === COMPOSE_ENVFILE)).toBe(false);
    } finally {
      delete process.env[FLAG];
    }
  });
});
