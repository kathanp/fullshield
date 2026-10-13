import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { scanDockerfile } from '../../../../src/modules/config/dockerfile.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

const SEEDED = [
  'CONFIG-HELMET-001',
  'CONFIG-BODYLIMIT-001',
  'CONFIG-CORS-001',
  'CONFIG-RATELIMIT-001',
  'CONFIG-ERRSTACK-001',
  'CONFIG-DOCKER-LATEST-001',
  'CONFIG-DOCKER-ROOT-001',
  'CONFIG-DOCKER-ENV-001',
];

describe('config module on fixtures', () => {
  it('detects seeded config issues in vulnerable-app', async () => {
    const result = await scan({ cwd: vulnerableApp, modules: ['config'] });
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const id of SEEDED) {
      expect(ids, `expected ${id}`).toContain(id);
    }
  });

  it('produces zero high/critical config findings on clean-app', async () => {
    const result = await scan({ cwd: cleanApp, modules: ['config'] });
    expect(result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')).toEqual([]);
  });
});

describe('scanDockerfile', () => {
  it('flags :latest, missing USER, and ENV secrets', () => {
    const findings = scanDockerfile(
      'Dockerfile',
      'FROM node:latest\nENV API_SECRET=x\nCMD node\n',
    );
    expect(findings.map((f) => f.ruleId).sort()).toEqual([
      'CONFIG-DOCKER-ENV-001',
      'CONFIG-DOCKER-LATEST-001',
      'CONFIG-DOCKER-ROOT-001',
    ]);
  });

  it('does not flag a pinned image with a non-root USER', () => {
    const findings = scanDockerfile('Dockerfile', 'FROM node:20-bookworm-slim\nUSER node\n');
    expect(findings).toEqual([]);
  });
});
