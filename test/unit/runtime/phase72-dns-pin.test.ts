import { afterEach, describe, expect, it } from 'vitest';

import { enterRaspContext } from '../../../src/runtime/rasp/context.js';
import { disableRasp } from '../../../src/runtime/rasp/enable.js';
import { dnsPinBlocks, hostIsBlocked, setDnsPinTtlMs, setSsrfLookup } from '../../../src/runtime/rasp/ssrf.js';
import type { RaspRequestContext } from '../../../src/runtime/rasp/types.js';
import { scoreCorpus } from '../../../src/runtime/rasp/decide.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ctx: RaspRequestContext = { path: '/', ip: 'test', strings: [], objects: [] };

afterEach(() => {
  disableRasp();
  setSsrfLookup(undefined);
  setDnsPinTtlMs(undefined);
});

describe('phase 72 dns pin', () => {
  it('blocks a private rebinding inside the TTL and allows a public address after expiry', () => {
    enterRaspContext(ctx, () => {
      expect(dnsPinBlocks('cdn.example', ['1.1.1.1'], 1_000)).toBe(false);
      expect(dnsPinBlocks('cdn.example', ['127.0.0.1'], 1_000 + 1_000)).toBe(true);
      setDnsPinTtlMs(5_000);
      expect(dnsPinBlocks('cdn.example', ['8.8.8.8'], 1_000 + 60_000)).toBe(false);
    });
  });

  it('uses the mock resolver on the outbound check and fails open when lookup throws', () => {
    let calls = 0;
    setSsrfLookup(() => {
      calls += 1;
      if (calls === 1) return ['1.1.1.1'];
      if (calls === 2) return ['127.0.0.1'];
      throw new Error('resolver down');
    });
    setDnsPinTtlMs(60_000);
    enterRaspContext(ctx, () => {
      expect(hostIsBlocked('cdn.example')).toBe(false);
      expect(hostIsBlocked('cdn.example')).toBe(true);
      expect(hostIsBlocked('cdn.example')).toBe(false);
    });
  });

  it('keeps the benign corpus at zero blocked', () => {
    const benign = JSON.parse(
      readFileSync(join(import.meta.dirname, '../../fixtures/rasp/benign-corpus.json'), 'utf8'),
    ) as { cases: Array<Record<string, unknown>> };
    const result = scoreCorpus(benign.cases);
    expect(result.blocked).toBe(0);
  });
});
