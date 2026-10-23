/**
 * Phase 404. Runtime config validation.
 * Off unless FULLSHIELD_EXPERIMENTAL_RUNCFG=1.
 * The schema document below is the one object used for scanner and runtime fixtures.
 * It is not fetched.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNCFG';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export const CONFIG_SCHEMA = {
  $id: 'fullshield-config',
  type: 'object',
  additionalProperties: false,
  properties: {
    mode: { enum: ['monitor', 'block'] },
    fraction: { type: 'number', minimum: 0, maximum: 1 },
    monitorLogger: { type: 'boolean' },
    redis: { enum: ['memory', 'redis'] },
    redisUrl: { type: 'string' },
    ssrfAllow: { type: 'array', items: { type: 'string' } },
    advisoryMaxAge: { type: 'string' },
  },
} as const;

const KEYS = new Set(Object.keys(CONFIG_SCHEMA.properties));
const METADATA = '169.254.169.254';

export interface ConfigDecision {
  listen: boolean;
}

export function validateConfig(config: Record<string, unknown>): ConfigDecision {
  if (!enabled()) {
    return { listen: true };
  }
  for (const key of Object.keys(config)) {
    if (!KEYS.has(key)) {
      throw new FsError(`unknown key ${key}`);
    }
  }
  if (config.mode === 'block' && config.fraction === 0 && config.monitorLogger !== true) {
    throw new FsError('block mode with fraction 0 and no monitor logger');
  }
  if (config.redis === 'redis' && (typeof config.redisUrl !== 'string' || config.redisUrl === '')) {
    throw new FsError('redis mode with no URL');
  }
  if (Array.isArray(config.ssrfAllow) && config.ssrfAllow.includes(METADATA)) {
    throw new FsError('metadata address on the SSRF allowlist');
  }
  return { listen: true };
}
