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
});
