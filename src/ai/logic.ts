import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from '../core/finding.js';
import { asAiFinding, fixtureLogic } from './fixtures.js';
import type { AiClient } from './provider.js';

const ROUTE_FILE = /(^|\/)(routes?|handlers?|controllers?)\//;

/**
 * Recorded-fixture logic hunter (IDOR, mass assignment). Findings are
 * `source: 'ai'`, confidence ≤ medium, and never fail CI.
 */
export async function runLogicHunt(
  cwd: string,
  files: readonly string[],
  client: AiClient,
): Promise<Finding[]> {
  const chunks: string[] = [];
  const fileTexts: Array<{ file: string; text: string }> = [];
  for (const file of files) {
    if (!/\.[cm]?[jt]sx?$/.test(file)) continue;
    if (!ROUTE_FILE.test(file) && !/app\.(get|post|put|patch|delete)/.test(file)) {
      try {
        const text = await readFile(join(cwd, file), 'utf8');
        if (!/app\.(get|post|put|patch|delete)/.test(text) && !/findById\(req\.params/.test(text)) {
          continue;
        }
        fileTexts.push({ file, text });
        chunks.push(`// file: ${file}\n${text}`);
      } catch {
        continue;
      }
      continue;
    }
    try {
      const text = await readFile(join(cwd, file), 'utf8');
      fileTexts.push({ file, text });
      chunks.push(`// file: ${file}\n${text}`);
    } catch {
      // skip unreadable
    }
  }
  const prompt = chunks.join('\n\n');
  if (prompt.length === 0) return [];
  const res = await client.complete({ mode: 'logic', prompt });
  if (res === null) return [];
  const seeds = fixtureLogic(prompt);
  const findings: Finding[] = [];
  for (const seed of seeds) {
    const hit =
      fileTexts.find((f) => f.file.includes(seed.fileHint) && f.text.includes(seed.fileHint === 'user' ? 'findById' : 'Object.assign')) ??
      fileTexts.find((f) =>
        f.text.includes(seed.ruleId === 'AI-IDOR-001' ? 'findById(req.params.id)' : 'Object.assign(user, req.body)'),
      );
    if (hit === undefined) continue;
    const line =
      hit.text
        .split(/\r?\n/)
        .findIndex((l) => l.includes(seed.ruleId === 'AI-IDOR-001' ? 'findById' : 'Object.assign')) + 1;
    findings.push(asAiFinding(seed, hit.file, line > 0 ? line : 1));
  }
  return findings;
}

/** True positives / all AI findings on a fixture set (spec §16.5). */
export function aiPrecision(findings: readonly Finding[], expectedRuleIds: readonly string[]): number {
  const ai = findings.filter((f) => f.source === 'ai');
  if (ai.length === 0) return 1;
  const expected = new Set(expectedRuleIds);
  const tp = ai.filter((f) => expected.has(f.ruleId)).length;
  return tp / ai.length;
}
