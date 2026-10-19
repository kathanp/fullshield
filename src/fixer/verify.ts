import { runSastOnText } from '../modules/sast/engine.js';
import type { Finding } from '../core/finding.js';

export type FixVerification = 'removes-finding' | 'does-not-remove' | 'introduces-finding';

export function verifyEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_FIX_VERIFY === '1';
}

/** Re-scan the patched file. Does not execute the project. */
export async function verifyPatchedSource(
  file: string,
  before: string,
  after: string,
  ruleId: string,
): Promise<FixVerification> {
  const prior = new Set((await runSastOnText(file, before)).map((finding) => finding.ruleId));
  const next = await runSastOnText(file, after);
  const nextIds = new Set(next.map((finding) => finding.ruleId));
  for (const id of nextIds) {
    if (!prior.has(id)) return 'introduces-finding';
  }
  if (prior.has(ruleId) && !nextIds.has(ruleId)) return 'removes-finding';
  return 'does-not-remove';
}

export function mayWrite(status: FixVerification, forceUnverified: boolean): boolean {
  if (status === 'introduces-finding') return false;
  if (status === 'does-not-remove') return forceUnverified;
  return true;
}

export function annotateVerification(finding: Finding, status: FixVerification): Finding {
  return { ...finding, verified: status };
}
