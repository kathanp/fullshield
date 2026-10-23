/**
 * Phase 369. VEX justified by reachability evidence.
 * Off unless FULLSHIELD_EXPERIMENTAL_VEX2=1.
 * Constrains this tool's emitter only.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_VEX2';
export const DYNAMIC_IMPORT_FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_REACH_DYNAMIC';

/** Fixed text. Names the engine version and the class it does not understand. */
export const DYNAMIC_IMPORT_LIMIT =
  'reachability engine version 369; classes not understood: dynamic import';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type ReachClass =
  | 'symbol-not-called'
  | 'not-imported'
  | 'reachability-unknown'
  | 'function-reachable-via-dependency'
  | 'reachable';

export interface AdvisoryReach {
  id: string;
  reachability: ReachClass;
  witness?: string;
}

export interface VexStatement {
  id: string;
  status: 'not_affected';
  reachability: 'symbol-not-called' | 'not-imported';
  evidence: string;
  justification: string;
}

export interface VexDocument {
  statements: VexStatement[];
  /** Advisories that stay in the scan (not emitted as not-affected). */
  remainInScan: string[];
}

const NOT_AFFECTED = new Set<ReachClass>(['symbol-not-called', 'not-imported']);

export function emitVex(advisories: readonly AdvisoryReach[], previousBytes: string): string {
  if (!enabled()) {
    return previousBytes;
  }
  return JSON.stringify(buildVex(advisories));
}

export function buildVex(advisories: readonly AdvisoryReach[]): VexDocument {
  const statements: VexStatement[] = [];
  const remainInScan: string[] = [];
  const dynamicOff = process.env[DYNAMIC_IMPORT_FLAG] !== '1';
  for (const advisory of advisories) {
    if (!NOT_AFFECTED.has(advisory.reachability) || advisory.witness === undefined || advisory.witness === '') {
      remainInScan.push(advisory.id);
      continue;
    }
    const reachability = advisory.reachability as 'symbol-not-called' | 'not-imported';
    let justification = advisory.witness;
    if (dynamicOff && reachability === 'not-imported') {
      justification = `${advisory.witness}; ${DYNAMIC_IMPORT_LIMIT}`;
    }
    statements.push({
      id: advisory.id,
      status: 'not_affected',
      reachability,
      evidence: advisory.witness,
      justification,
    });
  }
  return { statements, remainInScan };
}

export function validateVex(document: VexDocument): string[] {
  const errors: string[] = [];
  for (const statement of document.statements) {
    if (statement.evidence === undefined || statement.evidence === '') {
      errors.push(`${statement.id} lacks evidence`);
    }
    if (statement.status !== 'not_affected') {
      errors.push(`${statement.id} status`);
    }
    if (statement.reachability !== 'symbol-not-called' && statement.reachability !== 'not-imported') {
      errors.push(`${statement.id} class`);
    }
  }
  return errors;
}
