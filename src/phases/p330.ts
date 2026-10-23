/**
 * Phase 330. Access-control matrix report.
 * Off unless FULLSHIELD_EXPERIMENTAL_ACLREPORT=1.
 * Adds no findings. Flag off, the option fails with FS-E330 and the file is not written.
 */

import { matrixRows, type MatrixRoute, type MatrixRow } from './p313.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ACLREPORT';
export const HEADER = 'The cells are IR edges, not a proof of exposure.';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

class AccessReportError extends Error {
  readonly code = 'FS-E330';
  constructor(message: string) {
    super(`FS-E330 ${message}`);
    this.name = 'AccessReportError';
  }
}

export interface AccessScan {
  findings: readonly { id?: string; ruleId: string }[];
}

export interface AccessReport {
  header: string;
  rows: MatrixRow[];
  findingIds: { ruleId: string; ids: string[] }[];
}

const LINKED = ['SAST-IDOR-002', 'SAST-MASSASSIGN-001', 'CONFIG-CSRF-001', 'SAST-TENANT-001', 'SAST-GQL-AUTHZ-001'] as const;

export function buildAccessReport(routes: readonly MatrixRoute[], scan: AccessScan): AccessReport {
  const grouped = new Map<string, string[]>();
  for (const ruleId of LINKED) {
    grouped.set(ruleId, []);
  }
  for (const finding of scan.findings) {
    grouped.get(finding.ruleId)?.push(finding.id ?? finding.ruleId);
  }
  const findingIds = [...grouped.entries()]
    .map(([ruleId, ids]) => ({ ruleId, ids: [...ids].sort((a, b) => a.localeCompare(b)) }))
    .filter((entry) => entry.ids.length > 0);
  const report: AccessReport = { header: HEADER, rows: matrixRows(routes), findingIds };
  if (!report.header.includes('IR edges') || !report.header.includes('not a proof of exposure')) {
    throw new AccessReportError('report header is missing the IR-edge sentence');
  }
  for (const row of report.rows) {
    if (row.auth === 'safe' || row.authz === 'safe' || row.ownerScope === 'safe') {
      throw new AccessReportError('report used a forbidden cell token');
    }
  }
  return report;
}

export function accessReport(
  scan: AccessScan,
  routes: readonly MatrixRoute[],
  option: { path?: string; write?: (path: string, body: string) => void } = {},
): AccessScan {
  if (!enabled()) {
    if (option.path !== undefined) {
      throw new AccessReportError('FULLSHIELD_EXPERIMENTAL_ACLREPORT');
    }
    return scan;
  }
  if (option.path === undefined) {
    return scan;
  }
  option.write?.(option.path, JSON.stringify(buildAccessReport(routes, scan)));
  return scan;
}
