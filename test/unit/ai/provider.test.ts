import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { createAiClient } from '../../../src/ai/provider.js';
import { redactSecrets, wrapUntrustedCode } from '../../../src/ai/redact.js';
import { scan } from '../../../src/core/engine.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const AWS = 'AKIAIOSFODNN7EXAMPLE';

describe('AI provider layer (Phase 14)', () => {
  it('makes zero network calls when --ai is off', async () => {
    const fetchImpl = vi.fn(() => {
      throw new Error('network should not be used');
    });
    const client = createAiClient({ enabled: false, fetchImpl, useFixtures: false, apiKey: 'k' });
    await expect(client.complete({ mode: 'triage', prompt: 'hi' })).resolves.toBeNull();
    expect(client.networkCalls).toBe(0);
    expect(fetchImpl).not.toHaveBeenCalled();

    const spy = vi.spyOn(globalThis, 'fetch');
    await scan({ cwd: cleanApp, offline: true });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('redacts secrets from the outbound payload and never sends the raw key', async () => {
    const wrapped = wrapUntrustedCode(`const k = '${AWS}';`);
    expect(wrapped).toContain('<REDACTED>');
    expect(wrapped).not.toContain(AWS);
    expect(redactSecrets(`sk-ant-abcdefghijklmnopqrstuvwxyz`)).toContain('<REDACTED>');

    const fetchImpl = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ content: '{"verdict":"needs-review"}' }),
      }),
    );
    const client = createAiClient({
      enabled: true,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      useFixtures: false,
      apiKey: 'test-key',
      provider: 'openai',
    });
    const res = await client.complete({ mode: 'triage', prompt: `key ${AWS} in code` });
    expect(res?.redactedPrompt).not.toContain(AWS);
    expect(res?.redactedPrompt).toContain('<REDACTED>');
    const firstCall = fetchImpl.mock.calls[0] as unknown as [string, { body?: string }] | undefined;
    const body = String(firstCall?.[1]?.body ?? '');
    expect(body).not.toContain(AWS);
    expect(body).toContain('<REDACTED>');
  });

  it('enforces the cost cap and caches identical prompts', async () => {
    const client = createAiClient({
      enabled: true,
      useFixtures: true,
      config: { enabled: true, maxCostUsd: 0.015, maxFindings: 50 },
    });
    const first = await client.complete({ mode: 'explain', prompt: 'same' });
    const cached = await client.complete({ mode: 'explain', prompt: 'same' });
    const third = await client.complete({ mode: 'explain', prompt: 'other' });
    expect(first?.cached).toBe(false);
    expect(cached?.cached).toBe(true);
    expect(cached?.costUsd).toBe(0);
    expect(third).toBeNull();
    expect(client.spentUsd).toBeLessThanOrEqual(0.015);
  });

  it('retries invalid live JSON once then drops it', async () => {
    let n = 0;
    const fetchImpl = vi.fn(() => {
      n += 1;
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ content: n === 1 ? 'not-json' : '{"verdict":"needs-review"}' }),
      });
    });
    const client = createAiClient({
      enabled: true,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      useFixtures: false,
      apiKey: 'k',
      provider: 'anthropic',
    });
    const res = await client.complete({ mode: 'triage', prompt: 'x' });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(res?.json).toEqual({ verdict: 'needs-review' });
  });
});
