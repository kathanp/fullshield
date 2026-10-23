/**
 * Phase 316. Role-field mass assignment.
 * Off unless FULLSHIELD_EXPERIMENTAL_MASSASSIGN=1.
 * Tags win. The default name list applies only when the model has no tags.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MASSASSIGN';
export const RULE = 'SAST-MASSASSIGN-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const DEFAULT_PRIVILEGE = ['role', 'isAdmin', 'permissions', 'tenantId'] as const;

export interface MassModel {
  tags?: Readonly<Record<string, 'privilege' | 'plain'>>;
}

export interface MassWrite {
  file: string;
  line: number;
  keys: readonly string[] | 'unknown';
  transfer?: { kind: 'pick' | 'dto' | 'removeAdditional'; keys: readonly string[] };
  model?: MassModel;
}

export interface MassConfig {
  extraNames?: readonly string[];
}

export interface MassFinding {
  ruleId: typeof RULE;
  severity: 'high';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

function privilegeSet(model: MassModel | undefined, config: MassConfig): { names: Set<string>; byName: boolean } {
  const tags = model?.tags;
  if (tags !== undefined && Object.keys(tags).length > 0) {
    const names = new Set<string>();
    for (const [field, tag] of Object.entries(tags)) {
      if (tag === 'privilege') {
        names.add(field);
      }
    }
    return { names, byName: false };
  }
  return { names: new Set<string>([...DEFAULT_PRIVILEGE, ...(config.extraNames ?? [])]), byName: true };
}

export function massFindings(writes: readonly MassWrite[], config: MassConfig = {}): MassFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: MassFinding[] = [];
  for (const write of writes) {
    const privilege = privilegeSet(write.model, config);
    const keys = write.transfer?.keys ?? write.keys;
    if (keys === 'unknown') {
      findings.push({
        ruleId: RULE,
        severity: 'high',
        confidence: 'medium',
        file: write.file,
        line: write.line,
        message: 'Create or update data has unknown keys.',
        witness: 'unknown keys',
      });
      continue;
    }
    const hit = keys.filter((key) => privilege.names.has(key));
    if (hit.length === 0) {
      continue;
    }
    const listed = hit.join(', ');
    findings.push({
      ruleId: RULE,
      severity: 'high',
      confidence: 'medium',
      file: write.file,
      line: write.line,
      message: privilege.byName ? `Create or update data includes ${listed}. The match was by name.` : `Create or update data includes ${listed}.`,
      witness: listed,
    });
  }
  return findings;
}
