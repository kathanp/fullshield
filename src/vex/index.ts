import { createHash } from 'node:crypto';

import type { Finding } from '../core/finding.js';
import { validateCycloneDx15 } from '../sbom/cyclonedx.js';

const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0';
const OPENVEX_NOT_AFFECTED_JUSTIFICATION = 'vulnerable_code_not_in_execute_path';
const CDX_NOT_AFFECTED_JUSTIFICATION = 'code_not_reachable';

const OPENVEX_STATUSES = new Set(['not_affected', 'affected', 'fixed', 'under_investigation']);

export type VexFormat = 'openvex' | 'cyclonedx';

function depFindings(findings: readonly Finding[]): Finding[] {
  return findings.filter((f) => f.ruleId === 'DEPS-VULN-001');
}

function vulnName(finding: Finding): string {
  return (
    finding.references?.find((r) => r.startsWith('CVE-') || r.startsWith('GHSA-') || r.startsWith('MAL-')) ??
    finding.id
  );
}

function npmPurl(snippet: string | undefined): string {
  const raw = snippet ?? 'unknown@0.0.0';
  let name: string;
  let version: string;
  if (raw.startsWith('@')) {
    const second = raw.indexOf('@', 1);
    name = second === -1 ? raw : raw.slice(0, second);
    version = second === -1 ? '0.0.0' : raw.slice(second + 1);
  } else {
    const at = raw.indexOf('@');
    name = at <= 0 ? raw : raw.slice(0, at);
    version = at <= 0 ? '0.0.0' : raw.slice(at + 1);
  }
  return `pkg:npm/${encodeURIComponent(name)}@${version}`;
}

function notImported(finding: Finding): boolean {
  return finding.reachability === 'not-imported';
}

function openVexStatement(finding: Finding): Record<string, unknown> {
  const base = {
    vulnerability: { name: vulnName(finding) },
    products: [{ '@id': npmPurl(finding.snippet) }],
  };
  const detail =
    process.env.FULLSHIELD_EXPERIMENTAL_SBOM_REACH === '1' && finding.reachabilityEvidence?.reason !== undefined
      ? { detail: finding.reachabilityEvidence.reason }
      : {};
  if (notImported(finding)) {
    return {
      ...base,
      status: 'not_affected',
      justification: OPENVEX_NOT_AFFECTED_JUSTIFICATION,
      ...detail,
    };
  }
  return { ...base, status: 'under_investigation', ...detail };
}

export function buildOpenVex(findings: readonly Finding[]): Record<string, unknown> {
  const statements = depFindings(findings).map(openVexStatement);
  const timestamp = new Date().toISOString();
  const idSeed = JSON.stringify(statements);
  const digest = createHash('sha256').update(idSeed).digest('hex').slice(0, 16);
  return {
    '@context': OPENVEX_CONTEXT,
    '@id': `https://openvex.dev/docs/public/fullshield-${digest}`,
    author: 'FullShield',
    timestamp,
    version: 1,
    statements,
  };
}

export function validateOpenVex(doc: unknown): string[] {
  const errors: string[] = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['OpenVEX document must be an object'];
  }
  const root = doc as Record<string, unknown>;
  if (typeof root['@context'] !== 'string' || !String(root['@context']).includes('openvex')) {
    errors.push('@context must be an OpenVEX context URI');
  }
  if (typeof root['@id'] !== 'string' || root['@id'].length === 0) {errors.push('@id is required');}
  if (typeof root.author !== 'string' || root.author.length === 0) {errors.push('author is required');}
  if (typeof root.timestamp !== 'string' || root.timestamp.length === 0) {errors.push('timestamp is required');}
  if (typeof root.version !== 'number') {errors.push('version must be a number');}
  if (!Array.isArray(root.statements)) {
    errors.push('statements must be an array');
    return errors;
  }
  for (const [i, raw] of root.statements.entries()) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      errors.push(`statements[${i}] must be an object`);
      continue;
    }
    const stmt = raw as Record<string, unknown>;
    if (typeof stmt.vulnerability !== 'object' || stmt.vulnerability === null) {
      errors.push(`statements[${i}].vulnerability is required`);
    }
    if (!Array.isArray(stmt.products) || stmt.products.length === 0) {
      errors.push(`statements[${i}].products must be a non-empty array`);
    }
    if (typeof stmt.status !== 'string' || !OPENVEX_STATUSES.has(stmt.status)) {
      errors.push(`statements[${i}].status is invalid`);
      continue;
    }
    if (stmt.status === 'not_affected') {
      if (stmt.justification !== OPENVEX_NOT_AFFECTED_JUSTIFICATION) {
        errors.push(
          `statements[${i}]: not_affected requires justification ${OPENVEX_NOT_AFFECTED_JUSTIFICATION}`,
        );
      }
    }
  }
  return errors;
}

function cdxAnalysis(finding: Finding): { state: string; justification?: string } {
  if (notImported(finding)) {
    return { state: 'not_affected', justification: CDX_NOT_AFFECTED_JUSTIFICATION };
  }
  return { state: 'in_triage' };
}

export function buildCycloneDxVex(
  meta: { name: string; version: string },
  findings: readonly Finding[],
): Record<string, unknown> {
  return {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      component: { type: 'application', name: meta.name, version: meta.version },
    },
    components: [],
    vulnerabilities: depFindings(findings).map((f) => ({
      id: vulnName(f),
      description: f.message,
      affects: [{ ref: npmPurl(f.snippet) }],
      analysis: cdxAnalysis(f),
    })),
  };
}

export function validateCycloneDxVex(doc: unknown): string[] {
  const errors = validateCycloneDx15(doc);
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {return errors;}
  const root = doc as Record<string, unknown>;
  if (!Array.isArray(root.vulnerabilities)) {
    errors.push('vulnerabilities must be an array');
    return errors;
  }
  for (const [i, raw] of root.vulnerabilities.entries()) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      errors.push(`vulnerabilities[${i}] must be an object`);
      continue;
    }
    const vuln = raw as Record<string, unknown>;
    if (typeof vuln.analysis !== 'object' || vuln.analysis === null || Array.isArray(vuln.analysis)) {
      errors.push(`vulnerabilities[${i}].analysis is required`);
      continue;
    }
    const analysis = vuln.analysis as Record<string, unknown>;
    if (typeof analysis.state !== 'string' || analysis.state.length === 0) {
      errors.push(`vulnerabilities[${i}].analysis.state is required`);
      continue;
    }
    if (analysis.state === 'not_affected' && analysis.justification !== CDX_NOT_AFFECTED_JUSTIFICATION) {
      errors.push(
        `vulnerabilities[${i}]: not_affected requires justification ${CDX_NOT_AFFECTED_JUSTIFICATION}`,
      );
    }
  }
  return errors;
}

export function buildVex(
  findings: readonly Finding[],
  format: VexFormat,
  meta: { name: string; version: string } = { name: 'app', version: '0.0.0' },
): Record<string, unknown> {
  if (format === 'cyclonedx') {return buildCycloneDxVex(meta, findings);}
  return buildOpenVex(findings);
}
