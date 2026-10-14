import { createHash } from 'node:crypto';

import type { AiConfig } from '../core/config.js';
import { extractJson, modeInstruction } from './parse.js';
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
  useFixtures: boolean;
  networkCalls: number;
  spentUsd: number;
  complete(req: AiCompleteRequest): Promise<AiCompleteResponse | null>;
}

const FIXTURE_COST = 0.01;

/** Live provider is opt-in via FULLSHIELD_AI_LIVE=1 (used by `npm run test:live-ai`). */
export function isLiveAi(): boolean {
  return process.env.FULLSHIELD_AI_LIVE === '1';
}

function cacheKey(model: string, prompt: string): string {
  return createHash('sha256').update(`${model}\0${prompt}`).digest('hex');
}

function providerUrl(provider: AiProviderName): string {
  if (provider === 'anthropic') return 'https://api.anthropic.com/v1/messages';
  if (provider === 'ollama') return 'http://127.0.0.1:11434/api/chat';
  return 'https://api.openai.com/v1/chat/completions';
}

function messageText(payload: unknown): string {
  if (typeof payload !== 'object' || payload === null) return '';
  const rec = payload as Record<string, unknown>;
  const msg = rec.message;
  if (typeof msg === 'object' && msg !== null && typeof (msg as { content?: unknown }).content === 'string') {
    return (msg as { content: string }).content;
  }
  if (typeof rec.content === 'string') return rec.content;
  const choices = rec.choices;
  if (Array.isArray(choices)) {
    const first = choices[0] as { message?: { content?: string } } | undefined;
    if (typeof first?.message?.content === 'string') return first.message.content;
  }
  return '';
}

/**
 * AI provider. Off by default. CI and the default path use recorded fixtures
 * and never open a socket. A live provider is used only when `useFixtures`
 * is false — tests inject `fetchImpl`; `test:live-ai` talks to local Ollama.
 */
export function createAiClient(options: AiClientOptions): AiClient {
  const cfg = options.config ?? { enabled: options.enabled, maxCostUsd: 1, maxFindings: 50 };
  const useFixtures = options.useFixtures ?? !isLiveAi();
  const model =
    options.model ?? process.env.FULLSHIELD_AI_MODEL ?? (useFixtures ? 'recorded-fixture' : 'qwen2.5-coder:7b');
  const provider: AiProviderName =
    options.provider ??
    (process.env.FULLSHIELD_AI_PROVIDER as AiProviderName | undefined) ??
    (useFixtures ? 'fixture' : 'ollama');
  const cache = new Map<string, AiCompleteResponse>();
  let spentUsd = 0;
  let networkCalls = 0;
  const liveCost = provider === 'ollama' ? 0 : FIXTURE_COST;

  return {
    get enabled() {
      return options.enabled && cfg.enabled !== false;
    },
    useFixtures,
    get networkCalls() {
      return networkCalls;
    },
    get spentUsd() {
      return spentUsd;
    },
    async complete(req: AiCompleteRequest): Promise<AiCompleteResponse | null> {
      if (!options.enabled) return null;
      const redactedPrompt = `${modeInstruction(req.mode)}\n${wrapUntrustedCode(req.prompt)}`;
      const key = cacheKey(req.model ?? model, redactedPrompt);
      const cached = cache.get(key);
      if (cached !== undefined) {
        return { ...cached, cached: true, costUsd: 0 };
      }
      const callCost = useFixtures ? FIXTURE_COST : liveCost;
      if (callCost > 0 && spentUsd + callCost > cfg.maxCostUsd) return null;

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

      const outbound =
        provider === 'ollama'
          ? JSON.stringify({
              model: req.model ?? model,
              stream: false,
              format: 'json',
              messages: [
                { role: 'system', content: 'You are a security assistant. Reply with JSON only.' },
                { role: 'user', content: redactedPrompt },
              ],
            })
          : JSON.stringify({
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
          signal: AbortSignal.timeout(180_000),
        });
        const payload: unknown = await res.json();
        const text = messageText(payload);
        return extractJson(text.length > 0 ? text : JSON.stringify(payload));
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

      spentUsd += callCost;
      const response: AiCompleteResponse = {
        json,
        costUsd: callCost,
        cached: false,
        redactedPrompt,
      };
      cache.set(key, response);
      return response;
    },
  };
}
