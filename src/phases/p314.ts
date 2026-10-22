/**
 * Phase 314. Ownership data flow.
 * Off unless FULLSHIELD_EXPERIMENTAL_OWNERFLOW=1.
 * The owner field name comes from the model. A may-alias is unknown, not not-scoped.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_OWNERFLOW';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type OwnerCell = 'owner-scoped' | 'not-scoped' | 'unknown' | 'not-computed';

export interface ModelOwner {
  ownerField: string;
  understood: boolean;
}

export interface AccessQuery {
  filterKeys: readonly string[] | 'unknown' | 'unresolved';
  origins: Readonly<Record<string, 'principal' | 'request' | 'other'>>;
  flow: 'same-variable' | 'must-alias' | 'may-alias';
  mustAliasOn: boolean;
  lookupOrigin: 'principal' | 'request' | 'other';
}

export function computeOwnerCell(query: AccessQuery, model: ModelOwner | undefined): OwnerCell {
  if (model === undefined || !model.understood) {
    return 'unknown';
  }
  if (query.filterKeys === 'unresolved' || query.filterKeys === 'unknown' || query.flow === 'may-alias') {
    return 'unknown';
  }
  if (query.flow === 'must-alias' && !query.mustAliasOn) {
    return 'unknown';
  }
  const origin = query.origins[model.ownerField];
  const must = query.flow === 'same-variable' || (query.flow === 'must-alias' && query.mustAliasOn);
  if (must && origin === 'principal') {
    return 'owner-scoped';
  }
  if (!query.filterKeys.includes(model.ownerField) && query.lookupOrigin === 'request') {
    return 'not-scoped';
  }
  return 'unknown';
}

export function ownerCell(query: AccessQuery, model: ModelOwner | undefined): OwnerCell | undefined {
  if (!enabled()) {
    return undefined;
  }
  return computeOwnerCell(query, model);
}
