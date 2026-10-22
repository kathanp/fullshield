/**
 * Phase 401. Response field masking.
 * Off unless FULLSHIELD_EXPERIMENTAL_RESPMASK=1.
 * Default is report-only. Strip runs only when config says so. The value is not logged.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RESPMASK';
export const DEFAULT_MASK_FIELDS = ['password', 'resetToken', 'secret'] as const;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface MaskFinding {
  ruleId: 'SAST-RESPMASK-001';
  severity: 'medium';
  field: string;
  message: string;
}

export function responseFinding(modelFields: readonly string[], sentFields: readonly string[], removed: readonly string[] = []): MaskFinding | null {
  if (!enabled()) {
    return null;
  }
  const hidden = new Set(removed);
  for (const field of DEFAULT_MASK_FIELDS) {
    if (hidden.has(field)) {
      continue;
    }
    if (modelFields.includes(field) && sentFields.includes(field)) {
      return {
        ruleId: 'SAST-RESPMASK-001',
        severity: 'medium',
        field,
        message: `Response includes model field ${field}.`,
      };
    }
  }
  return null;
}

export function maskResponse(
  body: Record<string, unknown>,
  config: { strip: boolean; fields?: readonly string[]; nested?: readonly string[] },
): { body: Record<string, unknown>; log: string } {
  if (!enabled() || !config.strip) {
    return { body, log: '' };
  }
  const fields = config.fields ?? DEFAULT_MASK_FIELDS;
  const next: Record<string, unknown> = { ...body };
  for (const field of fields) {
    delete next[field];
  }
  for (const path of config.nested ?? []) {
    const parts = path.split('.');
    let current: Record<string, unknown> = next;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const key = parts[i];
      if (key === undefined) {
        break;
      }
      const child = current[key];
      if (typeof child !== 'object' || child === null) {
        current = {};
        break;
      }
      const copy = { ...(child as Record<string, unknown>) };
      current[key] = copy;
      current = copy;
    }
    const leaf = parts[parts.length - 1];
    if (leaf !== undefined) {
      delete current[leaf];
    }
  }
  return { body: next, log: `stripped ${fields.length} field names` };
}
