import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyBaseline, readBaseline, writeBaseline } from '../../../src/core/baseline.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';

const finding = (ruleId: string, file: string): Finding => ({
  id: makeFindingId(ruleId, file, ruleId),
  ruleId,
  module: 'sast',
  title: ruleId,
  severity: 'high',
  confidence: 'high',
  file,
  line: 1,
  message: ruleId,
  remediation: 'fix',
});

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-baseline-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('baseline', () => {
  it('suppresses previously recorded finding ids and leaves new ones', async () => {
    const oldOne = finding('SAST-SQLI-001', 'a.js');
    const fresh = finding('SAST-EVAL-001', 'b.js');
    const path = join(dir, '.fullshield-baseline.json');
    await writeBaseline(path, [oldOne]);
    const raw = await readFile(path, 'utf8');
    expect(raw).toContain(oldOne.id);

    const remaining = applyBaseline([oldOne, fresh], await readBaseline(path));
    expect(remaining.map((f) => f.ruleId)).toEqual(['SAST-EVAL-001']);
  });

  it('treats a missing baseline file as empty', async () => {
    const items = [finding('SAST-SQLI-001', 'a.js')];
    expect(applyBaseline(items, await readBaseline(join(dir, 'nope.json')))).toEqual(items);
  });
});
