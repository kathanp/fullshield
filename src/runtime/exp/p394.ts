/**
 * Phase 394. Per-hook overhead harness.
 * Off unless FULLSHIELD_EXPERIMENTAL_HOOKPERF=1.
 * Dev tooling. A thrown hook fails the harness. A slow hook does not.
 * Numbers are whatever the run produced and are labeled unreviewed.
 */
import { writeFileSync } from 'node:fs';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOOKPERF';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface HookSample {
  hook: string;
  p50: number;
  p95: number;
  p99: number;
}

export interface HarnessReport {
  unreviewed: true;
  reviewed: false;
  rows: HookSample[];
}

function quantile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) {
    return 0;
  }
  const index = Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1);
  return sorted[Math.max(0, index)] ?? 0;
}

export function runHookHarness(hooks: readonly { name: string; run: () => void }[], outFile: string, samples = 20): HarnessReport {
  if (!enabled()) {
    return { unreviewed: true, reviewed: false, rows: [] };
  }
  const rows: HookSample[] = [];
  for (const hook of hooks) {
    const times: number[] = [];
    for (let i = 0; i < samples; i += 1) {
      const start = performance.now();
      hook.run();
      times.push(performance.now() - start);
    }
    times.sort((left, right) => left - right);
    rows.push({
      hook: hook.name,
      p50: quantile(times, 0.5),
      p95: quantile(times, 0.95),
      p99: quantile(times, 0.99),
    });
  }
  const report: HarnessReport = { unreviewed: true, reviewed: false, rows };
  writeFileSync(outFile, JSON.stringify(report));
  return report;
}
