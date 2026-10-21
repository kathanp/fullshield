import type { Finding } from '../../../core/finding.js';
import { npmFlag, type NpmDepthInput, type NpmDepthRow } from './types.js';

export { auditDiff, nestedOverrideKey } from './audit-diff.js';
export {
  cyclonedxPurl,
  dedupeAdvisoryIds,
  dedupeAliases,
  fixedVersionForRange,
  purlFor,
  severityFromCvss,
  withoutWithdrawn,
} from './osv-read.js';

const LANE_FLAGS = [
  'NPM_OSV_RANGE',
  'NPM_OSV_WITHDRAWN',
  'NPM_OSV_CVSS',
  'NPM_OSV_ALIAS',
  'NPM_OSV_PURL',
  'NPM_FIX_NESTED',
  'NPM_SBOM_PURL',
  'NPM_AUDIT_DIFF',
] as const;

/** Phases 243–250 do not emit findings. */
export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!LANE_FLAGS.some((name) => npmFlag(name))) {return [];}
  await Promise.resolve(input);
  return [];
}

export const laneRows: readonly NpmDepthRow[] = [];
