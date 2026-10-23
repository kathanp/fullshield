/**
 * Phase 392. Optional Redis counter store.
 * Off unless FULLSHIELD_EXPERIMENTAL_REDISRL=1.
 * The client is loaded only when config selects Redis. No scanner import.
 * The key prefix is fixed and is not configurable to empty.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REDISRL';
export const KEY_PREFIX = 'fullshield:rl:';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CountClient {
  set(key: string, value: number): Promise<void> | void;
}

export interface CounterConfig {
  store: 'memory' | 'redis';
  url?: string;
}

export async function openCounter(
  config: CounterConfig,
  load: (name: string) => Promise<CountClient | null>,
): Promise<{ set(source: string, count: number): Promise<void>; imported: boolean }> {
  if (!enabled() || config.store !== 'redis') {
    const memory = new Map<string, number>();
    return {
      imported: false,
      set(source: string, count: number): Promise<void> {
        if (!Number.isInteger(count)) {
          throw new TypeError('counter value must be an integer');
        }
        memory.set(`${KEY_PREFIX}${source}`, count);
        return Promise.resolve();
      },
    };
  }
  if (config.url === undefined || config.url === '') {
    throw new TypeError('Redis is selected and no URL was configured');
  }
  const client = (await load('redis')) ?? (await load('ioredis'));
  if (client === null) {
    throw new TypeError('install redis or ioredis to use this feature');
  }
  return {
    imported: true,
    async set(source: string, count: number): Promise<void> {
      if (!Number.isInteger(count)) {
        throw new TypeError('counter value must be an integer');
      }
      await client.set(`${KEY_PREFIX}${source}`, count);
    },
  };
}
