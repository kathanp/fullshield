import { createServer, type IncomingMessage, type Server } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { assertLocalAgentApi, runAgent } from '../../../src/agent/index.js';

let work: string;
let bare: string;
const dirs: string[] = [];

async function tmp(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

function git(cwd: string, args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}

async function seedWorktree(): Promise<void> {
  work = await tmp('fullshield-agent-work-');
  bare = await tmp('fullshield-agent-bare-');
  execFileSync('git', ['init', '--bare'], { cwd: bare, stdio: 'ignore' });
  git(work, ['init', '-b', 'main']);
  git(work, ['config', 'user.email', 'agent@test.local']);
  git(work, ['config', 'user.name', 'Agent Test']);
  await writeFile(
    join(work, 'app.js'),
    `const express = require('express');\nconst app = express();\napp.use(express.json());\n`,
  );
  await writeFile(join(work, '.env'), 'SECRET=1\n');
  await writeFile(
    join(work, 'package.json'),
    JSON.stringify({ name: 'agent-app', private: true, scripts: { test: 'node -e "process.exit(0)"' } }, null, 2),
  );
  git(work, ['add', '.']);
  git(work, ['commit', '-m', 'init']);
  git(work, ['remote', 'add', 'origin', bare]);
  git(work, ['push', '-u', 'origin', 'main']);
}

function startMockGithub(): Promise<{ server: Server; base: string; posts: Array<{ url: string; body: unknown }> }> {
  const posts: Array<{ url: string; body: unknown }> = [];
  const server = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c as Buffer));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let body: unknown = raw;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        body = raw;
      }
      posts.push({ url: `${req.method} ${req.url}`, body });
      if (req.method === 'POST' && (req.url ?? '').includes('/pulls')) {
        res.writeHead(201, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ number: posts.filter((p) => p.url.includes('/pulls')).length, html_url: 'http://127.0.0.1/pr/1', merged: false }));
        return;
      }
      if (req.method === 'PUT' && (req.url ?? '').includes('/merge')) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ message: 'agent never merges' }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, base: `http://127.0.0.1:${port}`, posts });
    });
  });
}

beforeEach(async () => {
  await seedWorktree();
});

afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('Phase 24 remediation agent (experimental)', () => {
  it('is a no-op without experimental', async () => {
    const result = await runAgent({ cwd: work, apiBase: 'http://127.0.0.1:9', repo: 'acme/app' });
    expect(result.skipped).toBe(true);
    expect(result.prs).toEqual([]);
  });

  it('refuses a real GitHub or non-loopback API host', () => {
    expect(() => assertLocalAgentApi('https://api.github.com')).toThrow(/localhost|127\.0\.0\.1|network/i);
    expect(() => assertLocalAgentApi('http://example.com')).toThrow(/localhost|127\.0\.0\.1|network/i);
    expect(() => assertLocalAgentApi('http://192.168.1.4')).toThrow(/localhost|127\.0\.0\.1|network/i);
    expect(assertLocalAgentApi('http://127.0.0.1:9')).toBe(true);
    expect(assertLocalAgentApi('http://localhost:9')).toBe(true);
  });

  it('opens a PR against a mock GitHub API and a local bare remote, never main, never merge', async () => {
    const mock = await startMockGithub();
    try {
      const result = await runAgent({
        cwd: work,
        experimental: true,
        maxPrs: 3,
        maxFilesPerPr: 3,
        apiBase: mock.base,
        repo: 'acme/app',
        remote: 'origin',
      });
      expect(result.skipped).not.toBe(true);
      expect(result.prs.length).toBeGreaterThan(0);
      expect(result.merged).toBe(false);
      expect(result.pushedToProtected).toBe(false);
      const branches = execFileSync('git', ['--git-dir', bare, 'branch'], { encoding: 'utf8' });
      expect(branches).toMatch(/fullshield\/agent-/);
      expect(mock.posts.some((p) => p.url.startsWith('POST ') && p.url.includes('/pulls'))).toBe(true);
      expect(mock.posts.some((p) => p.url.includes('/merge'))).toBe(false);
      const pr = mock.posts.find((p) => p.url.includes('/pulls'))?.body as { head?: string; base?: string; body?: string };
      expect(pr.head).toMatch(/^fullshield\/agent-/);
      expect(pr.base).toBe('main');
      expect(pr.body).toMatch(/not merged/i);
      expect(pr.body).toMatch(/test/i);
    } finally {
      mock.server.close();
    }
  });

  it('stops on a project test failure and does not open further PRs', async () => {
    const mock = await startMockGithub();
    try {
      const result = await runAgent({
        cwd: work,
        experimental: true,
        maxPrs: 3,
        apiBase: mock.base,
        repo: 'acme/app',
        remote: 'origin',
        runTests: () => Promise.resolve({ ok: false, output: 'FAIL seeded' }),
      });
      expect(result.stoppedOnTestFailure).toBe(true);
      expect(result.prs).toEqual([]);
      expect(mock.posts.filter((p) => p.url.includes('/pulls'))).toEqual([]);
    } finally {
      mock.server.close();
    }
  });

  it('opens a PR when the patched file uses CRLF (core.autocrlf-independent)', async () => {
    await writeFile(
      join(work, 'app.js'),
      "const express = require('express');\r\nconst app = express();\r\napp.use(express.json());\r\n// crlf-fixture\r\n",
    );
    const mock = await startMockGithub();
    try {
      const result = await runAgent({
        cwd: work,
        experimental: true,
        maxPrs: 1,
        maxFilesPerPr: 1,
        apiBase: mock.base,
        repo: 'acme/app',
        remote: 'origin',
      });
      expect(result.skipped).not.toBe(true);
      expect(result.prs.length).toBeGreaterThan(0);
      expect(result.prs[0]?.files.some((f) => f.includes('\\'))).toBe(false);
    } finally {
      mock.server.close();
    }
  });

  it('does not touch more than maxFilesPerPr files in a PR', async () => {
    const mock = await startMockGithub();
    try {
      const result = await runAgent({
        cwd: work,
        experimental: true,
        maxPrs: 1,
        maxFilesPerPr: 1,
        apiBase: mock.base,
        repo: 'acme/app',
        remote: 'origin',
      });
      for (const pr of result.prs) {
        expect(pr.files.length).toBeLessThanOrEqual(1);
      }
    } finally {
      mock.server.close();
    }
  });
});
