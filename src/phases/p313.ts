/**
 * Phase 313. Route, auth, and data-access matrix.
 * Off unless FULLSHIELD_EXPERIMENTAL_ACLMATRIX=1.
 * Rows are not findings. Unknown is not printed as none.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ACLMATRIX';
export const OWNER_FLAG = 'FULLSHIELD_EXPERIMENTAL_OWNERFLOW';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface MatrixRoute {
  method: string;
  path: string;
  file: string;
  auth: string;
  authz: string;
  ownerScope?: string;
  sinks: readonly string[];
  message?: string;
}

export interface MatrixRow {
  method: string;
  path: string;
  file: string;
  auth: string;
  authz: string;
  ownerScope: string;
  sinks: string[];
}

export interface MatrixScan {
  findings: readonly { ruleId: string; message?: string }[];
  matrix?: MatrixRow[];
}

export function matrixRows(routes: readonly MatrixRoute[]): MatrixRow[] {
  const rows = routes.map((route) => ({
    method: route.method,
    path: route.path,
    file: route.file,
    auth: route.auth,
    authz: route.authz,
    ownerScope: process.env[OWNER_FLAG] === '1' ? (route.ownerScope ?? 'not-computed') : 'not-computed',
    sinks: [...route.sinks],
  }));
  rows.sort((a, b) => a.method.localeCompare(b.method) || a.path.localeCompare(b.path) || a.file.localeCompare(b.file));
  return rows;
}

export function explainMatrix(routes: readonly MatrixRoute[]): string {
  if (!enabled()) {
    return '';
  }
  const lines = ['method path auth authz owner-scope sinks'];
  for (const row of matrixRows(routes)) {
    lines.push(`${row.method} ${row.path} ${row.auth} ${row.authz} ${row.ownerScope} ${row.sinks.join(',')}`);
  }
  return lines.join('\n');
}

export function withMatrix(scan: MatrixScan, routes: readonly MatrixRoute[]): MatrixScan {
  if (!enabled()) {
    return scan;
  }
  return { findings: scan.findings, matrix: matrixRows(routes) };
}
