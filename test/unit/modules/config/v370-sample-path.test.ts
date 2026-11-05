import { describe, expect, it } from 'vitest';

import { runConfigAstChecks } from '../../../../src/modules/config/astChecks.js';
import { scanDockerfile } from '../../../../src/modules/config/dockerfile.js';

const APP = 'const express = require("express");\nconst app = express();\napp.use(express.json());\napp.post("/login", (req, res) => res.send("ok"));\nfunction fail(res, err) { res.send(err.stack); }\n';

async function ids(file: string): Promise<string[]> {
  const findings = await runConfigAstChecks(file, APP);
  return findings.map((finding) => finding.ruleId);
}

describe('3.7.0 sample paths for app-config rules', () => {
  it('still reports the five rules on application source', async () => {
    const found = await ids('server.js');
    expect(found).toContain('CONFIG-HELMET-001');
    expect(found).toContain('CONFIG-BODYLIMIT-001');
    expect(found).toContain('CONFIG-RATELIMIT-001');
    expect(found).toContain('CONFIG-ERRSTACK-001');
  });

  it('skips those rules under test, examples, and fixture trees, and on *.test.* files', async () => {
    for (const file of [
      'test/server.js',
      '__tests__/server.js',
      'examples/server.js',
      'example/server.js',
      'fixtures/server.js',
      'server.test.js',
    ]) {
      const found = await ids(file);
      expect(found, file).not.toContain('CONFIG-HELMET-001');
      expect(found, file).not.toContain('CONFIG-BODYLIMIT-001');
      expect(found, file).not.toContain('CONFIG-RATELIMIT-001');
      expect(found, file).not.toContain('CONFIG-ERRSTACK-001');
    }
  });

  it('still reports other config rules in a test file', async () => {
    const findings = await runConfigAstChecks(
      'test/cors.js',
      'cors({ origin: "*", credentials: true });\n',
    );
    expect(findings.map((finding) => finding.ruleId)).toContain('CONFIG-CORS-001');
  });

  it('skips CONFIG-DOCKER-ROOT-001 in fixtures and still reports :latest', () => {
    const findings = scanDockerfile('fixtures/Dockerfile', 'FROM node:latest\nCMD node\n');
    const ids = findings.map((finding) => finding.ruleId);
    expect(ids).not.toContain('CONFIG-DOCKER-ROOT-001');
    expect(ids).toContain('CONFIG-DOCKER-LATEST-001');
    const app = scanDockerfile('Dockerfile', 'FROM node:20\nCMD node\n');
    expect(app.map((finding) => finding.ruleId)).toContain('CONFIG-DOCKER-ROOT-001');
  });
});
