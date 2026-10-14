#!/usr/bin/env node
/**
 * Live Ollama smoke test. Never invoked by `npm run verify` or CI.
 *
 *   ollama serve && ollama pull qwen2.5-coder:7b
 *   npm run test:live-ai
 */
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { homedir } from 'node:os';
import { performance } from 'node:perf_hooks';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const model = process.env.FULLSHIELD_AI_MODEL ?? 'qwen2.5-coder:7b';
const host = process.env.FULLSHIELD_OLLAMA_URL ?? 'http://127.0.0.1:11434';

process.env.FULLSHIELD_AI_LIVE = '1';
process.env.FULLSHIELD_AI_INTERNAL = '1';
process.env.FULLSHIELD_AI_PROVIDER = 'ollama';
process.env.FULLSHIELD_AI_MODEL = model;
process.env.FULLSHIELD_AI_MAX_FINDINGS = process.env.FULLSHIELD_AI_MAX_FINDINGS ?? '8';

const dist = pathToFileURL(join(root, 'dist', 'index.js')).href;
const { scan, runAiFix, createAiClient } = await import(dist);

async function ping() {
  try {
    const res = await fetch(`${host}/api/tags`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    const names = (body.models ?? []).map((m) => m.name);
    const ok = names.some((n) => n.includes('qwen2.5-coder'));
    if (!ok) {
      throw new Error(`model ${model} missing (have: ${names.join(', ') || 'none'}). Run: ollama pull ${model}`);
    }
  } catch (error) {
    console.error(`live-ai: Ollama at ${host}: ${error instanceof Error ? error.message : error}`);
    process.exit(2);
  }
}

function summarizeAi(findings) {
  const labeled = findings.filter((f) => f.aiVerdict !== undefined);
  const explained = findings.filter((f) => typeof f.explanation === 'string');
  const ai = findings.filter((f) => f.source === 'ai');
  const verdicts = { 'true-positive': 0, 'likely-false-positive': 0, 'needs-review': 0 };
  for (const f of labeled) {
    if (verdicts[f.aiVerdict] !== undefined) verdicts[f.aiVerdict] += 1;
  }
  return {
    total: findings.length,
    labeled: labeled.length,
    explained: explained.length,
    aiAdded: ai.length,
    verdicts,
    labeledSample: labeled.slice(0, 16).map((f) => ({
      ruleId: f.ruleId,
      file: f.file,
      severity: f.severity,
      aiVerdict: f.aiVerdict,
      reasoning: (f.aiReasoning ?? '').slice(0, 240),
    })),
    aiSample: ai.slice(0, 16).map((f) => ({
      ruleId: f.ruleId,
      file: f.file,
      message: f.message,
    })),
    explainedSample: explained.slice(0, 6).map((f) => ({
      ruleId: f.ruleId,
      explanation: (f.explanation ?? '').slice(0, 320),
    })),
  };
}

async function timed(name, fn) {
  const t0 = performance.now();
  try {
    const value = await fn();
    return { name, ms: Math.round(performance.now() - t0), ok: true, value };
  } catch (error) {
    return {
      name,
      ms: Math.round(performance.now() - t0),
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function liveClient() {
  return createAiClient({ enabled: true, useFixtures: false, provider: 'ollama', model });
}

await ping();

const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const nodegoat = join(homedir(), 'fullshield-bench', 'NodeGoat');
const jobs = [];

jobs.push(
  await timed('vulnerable-app --ai triage', async () =>
    summarizeAi((await scan({ cwd: vulnerableApp, offline: true, ai: 'triage' })).findings),
  ),
);
jobs.push(
  await timed('vulnerable-app --ai explain', async () =>
    summarizeAi((await scan({ cwd: vulnerableApp, offline: true, ai: 'explain' })).findings),
  ),
);
jobs.push(
  await timed('vulnerable-app --ai logic', async () =>
    summarizeAi((await scan({ cwd: vulnerableApp, offline: true, ai: 'logic' })).findings),
  ),
);
jobs.push(
  await timed('vulnerable-app fix --ai', async () => runAiFix({ cwd: vulnerableApp, client: liveClient() })),
);

if (existsSync(nodegoat)) {
  jobs.push(
    await timed('NodeGoat --ai triage (sast,config,secrets)', async () =>
      summarizeAi(
        (
          await scan({
            cwd: nodegoat,
            offline: true,
            ai: 'triage',
            modules: ['sast', 'config', 'secrets'],
          })
        ).findings,
      ),
    ),
  );
  jobs.push(
    await timed('NodeGoat --ai explain (sast,config,secrets)', async () =>
      summarizeAi(
        (
          await scan({
            cwd: nodegoat,
            offline: true,
            ai: 'explain',
            modules: ['sast', 'config', 'secrets'],
          })
        ).findings,
      ),
    ),
  );
  jobs.push(
    await timed('NodeGoat --ai logic (sast)', async () =>
      summarizeAi((await scan({ cwd: nodegoat, offline: true, ai: 'logic', modules: ['sast'] })).findings),
    ),
  );
  jobs.push(
    await timed('NodeGoat fix --ai', async () => runAiFix({ cwd: nodegoat, client: liveClient() })),
  );
} else {
  jobs.push({ name: 'NodeGoat', ms: 0, ok: false, error: `missing ${nodegoat}` });
}

mkdirSync(join(root, 'benchmarks'), { recursive: true });
const rawPath = join(root, 'benchmarks', 'ai-live-raw.json');
writeFileSync(rawPath, JSON.stringify({ model, host, startedAt: new Date().toISOString(), jobs }, null, 2));
console.log(`live-ai: wrote ${rawPath}`);
for (const job of jobs) {
  console.log(`  [${job.ok ? 'ok' : 'FAIL'}] ${job.name} ${job.ms}ms`);
  if (!job.ok) console.log(`         ${job.error}`);
}
process.exit(jobs.some((j) => !j.ok) ? 1 : 0);
