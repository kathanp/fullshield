import { createHash } from 'node:crypto';

import type { AiConfig } from '../core/config.js';
import { wrapUntrustedCode } from './redact.js';

export type AiProviderName = 'anthropic' | 'openai' | 'ollama' | 'fixture';
export type AiMode = 'triage' | 'explain' | 'logic' | 'fix';

export interface AiCompleteRequest {
  mode: AiMode;
  prompt: string;
  model?: string;
}

export interface AiCompleteResponse {
  json: unknown;
  costUsd: number;
  cached: boolean;
  redactedPrompt: string;
}

export interface AiClientOptions {
  enabled: boolean;
  config?: AiConfig;
  /** Injected fetch for tests. Never used when fixtures are on. */
  fetchImpl?: typeof fetch;
  provider?: AiProviderName;
  apiKey?: string;
  model?: string;
  /** When true (default), only recorded fixtures are used — no network. */
  useFixtures?: boolean;
}

export interface AiClient {
  enabled: boolean;
  networkCalls: number;
  spentUsd: number;
  complete(req: AiCompleteRequest): Promise<AiCompleteResponse | null>;
}

const FIXTURE_COST = 0.01;

function cacheKey(model: string, prompt: string): string {
  return createHash('sha256').update(`${model}\0${prompt}`).digest('hex');
}

function providerUrl(provider: AiProviderName): string {
  if (provider === 'anthropic') return 'https://api.anthropic.com/v1/messages';
  if (provider === 'ollama') return 'http://127.0.0.1:11434/api/chat';
  return 'https://api.openai.com/v1/chat/completions';
}

function parseStructured(text: string): unknown {
  return JSON.parse(text) as unknown;
}

/**
 * AI provider. Off by default. CI and the default path use recorded fixtures
 * and never open a socket. A live provider is used only when `useFixtures`
 * is false and a key (or Ollama) is configured — tests inject `fetchImpl`.
 */
export function createAiClient(options: AiClientOptions): AiClient {
  const cfg = options.config ?? { enabled: options.enabled, maxCostUsd: 1, maxFindings: 50 };
  const useFixtures = options.useFixtures !== false;
  const model =
    options.model ?? process.env.FULLSHIELD_AI_MODEL ?? 'recorded-fixture';
  const provider: AiProviderName =
    options.provider ??
    (process.env.FULLSHIELD_AI_PROVIDER as AiProviderName | undefined) ??
    'fixture';
  const cache = new Map<string, AiCompleteResponse>();
  let spentUsd = 0;
  let networkCalls = 0;

  return {
    get enabled() {
      return options.enabled && cfg.enabled !== false;
    },
    get networkCalls() {
      return networkCalls;
    },
    get spentUsd() {
      return spentUsd;
    },
    async complete(req: AiCompleteRequest): Promise<AiCompleteResponse | null> {
      if (!options.enabled) return null;
      const redactedPrompt = wrapUntrustedCode(req.prompt);
      const key = cacheKey(req.model ?? model, redactedPrompt);
      const cached = cache.get(key);
      if (cached !== undefined) {
        return { ...cached, cached: true, costUsd: 0 };
      }
      if (spentUsd + FIXTURE_COST > cfg.maxCostUsd) return null;

      if (useFixtures) {
        spentUsd += FIXTURE_COST;
        const response: AiCompleteResponse = {
          json: { mode: req.mode, ok: true, prompt: redactedPrompt },
          costUsd: FIXTURE_COST,
          cached: false,
          redactedPrompt,
        };
        cache.set(key, response);
        return response;
      }

      const fetchImpl = options.fetchImpl ?? fetch;
      const apiKey = options.apiKey ?? process.env.FULLSHIELD_AI_KEY ?? '';
      if (provider !== 'ollama' && apiKey.length === 0) return null;

      const outbound = JSON.stringify({
        model: req.model ?? model,
        messages: [{ role: 'user', content: redactedPrompt }],
      });

      const doFetch = async (): Promise<unknown> => {
        networkCalls += 1;
        const res = await fetchImpl(providerUrl(provider), {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: apiKey.length > 0 ? `Bearer ${apiKey}` : '',
          },
          body: outbound,
        });
        const payload = (await res.json()) as { content?: string; choices?: Array<{ message?: { content?: string } }> };
        const text = payload.content ?? payload.choices?.[0]?.message?.content ?? '{}';
        return parseStructured(typeof text === 'string' ? text : JSON.stringify(text));
      };

      let json: unknown;
      try {
        json = await doFetch();
      } catch {
        try {
          json = await doFetch();
        } catch {
          return null;
        }
      }

      spentUsd += FIXTURE_COST;
      const response: AiCompleteResponse = {
        json,
        costUsd: FIXTURE_COST,
        cached: false,
        redactedPrompt,
      };
      cache.set(key, response);
      return response;
    },
  };
}
