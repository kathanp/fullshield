import type { Finding } from '../core/finding.js';

export interface SbomComponent {
  name: string;
  version: string;
  license?: string;
  purl?: string;
}

export interface SbomInput {
  name: string;
  version: string;
  components: SbomComponent[];
  findings?: Finding[];
}

export function validateCycloneDx15(doc: unknown): string[] {
  const errors: string[] = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['CycloneDX document must be an object'];
  }
  const root = doc as Record<string, unknown>;
  if (root.bomFormat !== 'CycloneDX') errors.push('bomFormat must be "CycloneDX"');
  if (root.specVersion !== '1.5') errors.push('specVersion must be "1.5"');
  if (!Array.isArray(root.components)) errors.push('components must be an array');
  return errors;
}

export function renderCycloneDx(input: SbomInput): Record<string, unknown> {
  const vulns = (input.findings ?? []).filter((f) => f.ruleId === 'DEPS-VULN-001');
  return {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      component: { type: 'application', name: input.name, version: input.version },
    },
    components: input.components.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      purl: c.purl ?? `pkg:npm/${encodeURIComponent(c.name)}@${c.version}`,
      ...(c.license !== undefined ? { licenses: [{ license: { id: c.license } }] } : {}),
    })),
    vulnerabilities: vulns.map((f) => ({
      id: f.references?.find((r) => r.startsWith('GHSA-') || r.startsWith('CVE-')) ?? f.id,
      description: f.message,
      affects: [{ ref: f.snippet ?? f.file }],
    })),
  };
}
