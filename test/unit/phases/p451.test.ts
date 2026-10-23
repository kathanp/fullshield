import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { DOCKER_ENV_COPY, DOCKER_NPM, DOCKER_USER, FLAG, scanDockerfile } from '../../../src/phases/p451.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('phase 451', () => {
  it('reports a final stage with no USER and a COPY of .env', () => {
    process.env[FLAG] = '1';
    const noUser = scanDockerfile('Dockerfile', 'FROM node:20\nCOPY package.json ./\n');
    expect(noUser.findings.some((row) => row.ruleId === DOCKER_USER)).toBe(true);
    const withUser = scanDockerfile('Dockerfile', 'FROM node:20\nUSER node\n');
    expect(withUser.findings.some((row) => row.ruleId === DOCKER_USER)).toBe(false);
    const env = scanDockerfile('Dockerfile', 'FROM node:20\nCOPY .env .\nUSER node\n');
    expect(env.findings.some((row) => row.ruleId === DOCKER_ENV_COPY)).toBe(true);
  });

  it('reports npm install beside a lockfile and not npm ci', () => {
    process.env[FLAG] = '1';
    const install = scanDockerfile('Dockerfile', 'FROM node:20\nCOPY package-lock.json ./\nRUN npm install\nUSER node\n');
    expect(install.findings.some((row) => row.ruleId === DOCKER_NPM)).toBe(true);
    const ci = scanDockerfile('Dockerfile', 'FROM node:20\nCOPY package-lock.json ./\nRUN npm ci\nUSER node\n');
    expect(ci.findings.some((row) => row.ruleId === DOCKER_NPM)).toBe(false);
    const bare = scanDockerfile('Dockerfile', 'FROM scratch\nRUN npm install\nUSER node\n');
    expect(bare.findings.some((row) => row.ruleId === DOCKER_NPM)).toBe(false);
  });

  it('records a parser failure instead of a clean result', () => {
    process.env[FLAG] = '1';
    const result = scanDockerfile('Dockerfile', 'FROM node:20\nRUN echo "hello\n');
    expect(result.clean).toBe(false);
    expect(result.events).toHaveLength(1);
  });

  it('returns the baseline when the flag is off and does not import a process API', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'Dockerfile', line: 1, message: 'kept' }];
    expect(scanDockerfile('Dockerfile', 'FROM node:20\n', baseline).findings).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p451.ts'), 'utf8');
    expect(src.includes('child_process')).toBe(false);
  });

  it('reports copied stages, orphan root stages, and a secret ARG', () => {
    process.env[FLAG] = '1';
    const token = `AKIA${'Z'.repeat(16)}`;
    try {
      const copied = scanDockerfile(
        'Dockerfile',
        'FROM node:20 AS builder\nRUN echo ok\nFROM node:20\nCOPY --from=builder /app /app\nUSER node\n',
      );
      expect(copied.findings.some((row) => row.ruleId === 'CONFIG-DOCKER-ROOT-STAGE-001')).toBe(false);
      const orphan = scanDockerfile('Dockerfile', 'FROM node:20 AS tools\nFROM node:20\nUSER node\n');
      expect(orphan.findings.some((row) => row.ruleId === 'CONFIG-DOCKER-ROOT-STAGE-001')).toBe(true);
      const secret = scanDockerfile('Dockerfile', `FROM node:20\nARG TOKEN=${token}\nUSER node\n`);
      expect(secret.findings.some((row) => row.ruleId === 'CONFIG-DOCKER-ARG-001')).toBe(true);
      const hidden = scanDockerfile('Dockerfile', `FROM node:20 AS build\nARG TOKEN=${token}\nFROM node:20\nUSER node\n`);
      expect(hidden.findings.some((row) => row.ruleId === 'CONFIG-DOCKER-ARG-001')).toBe(false);
      const forwarded = scanDockerfile(
        'Dockerfile',
        `FROM node:20 AS build\nARG TOKEN=${token}\nFROM node:20\nCOPY --from=build /opt /opt\nUSER node\n`,
      );
      expect(forwarded.findings.some((row) => row.ruleId === 'CONFIG-DOCKER-ARG-001')).toBe(true);
      process.env.FULLSHIELD_EXPERIMENTAL_DOCKERARG = '1';
      const skipped = scanDockerfile('Dockerfile', `FROM node:20\nARG TOKEN=${token}\nUSER 0\n`);
      expect(skipped.findings.some((row) => row.ruleId === 'CONFIG-DOCKER-ARG-001')).toBe(false);
      expect(skipped.findings.some((row) => row.ruleId === DOCKER_USER)).toBe(true);
      const rootUser = scanDockerfile('Dockerfile', 'FROM node:20\nUSER root\n');
      expect(rootUser.findings.some((row) => row.ruleId === DOCKER_USER)).toBe(true);
      const envFile = scanDockerfile('Dockerfile', 'FROM node:20\nCOPY secrets .env\nUSER node\n');
      expect(envFile.findings.some((row) => row.ruleId === DOCKER_ENV_COPY)).toBe(true);
      const spaced = scanDockerfile('Dockerfile', 'FROM node:20\r\n# note\r\n\r\nRUN echo early\r\nUSER node\r\n');
      expect(spaced.clean).toBe(true);
      expect(spaced.events).toEqual([]);
    } finally {
      delete process.env[FLAG];
      delete process.env.FULLSHIELD_EXPERIMENTAL_DOCKERARG;
    }
  });
});
