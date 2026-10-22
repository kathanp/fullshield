/**
 * Phase 432. CycloneDX 1.6.
 * Off unless FULLSHIELD_EXPERIMENTAL_CDX16=1.
 * Flag off, or without spec 1.6: the 1.5 document from the existing emitter.
 * Reachability is a namespaced property, omitted when it was not computed.
 */
import { renderCycloneDx, type SbomComponent, type SbomInput } from '../sbom/cyclonedx.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CDX16';
/** Documented name. Class names are not a CycloneDX enum. */
export const REACH_PROPERTY = 'fullshield:reachability-class';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface Component16 extends SbomComponent {
  hash?: { alg: string; content: string };
  /** Omitted from the document when undefined. Never filled with unknown. */
  reachClass?: string;
}

export interface BomRequest {
  name: string;
  version: string;
  components: Component16[];
  spec?: string;
}

function as15(request: BomRequest): SbomInput {
  return {
    name: request.name,
    version: request.version,
    components: request.components.map((component) => ({
      name: component.name,
      version: component.version,
      ...(component.purl !== undefined ? { purl: component.purl } : {}),
      ...(component.license !== undefined ? { license: component.license } : {}),
    })),
  };
}

function component16(component: Component16): Record<string, unknown> {
  const row: Record<string, unknown> = {
    type: 'library',
    name: component.name,
    version: component.version,
    purl: component.purl ?? `pkg:npm/${encodeURIComponent(component.name)}@${component.version}`,
  };
  if (component.hash !== undefined) {
    row.hashes = [{ alg: component.hash.alg, content: component.hash.content }];
  }
  if (component.reachClass !== undefined) {
    row.properties = [{ name: REACH_PROPERTY, value: component.reachClass }];
  }
  return row;
}

export function renderBom(request: BomRequest): Record<string, unknown> {
  if (!enabled() || request.spec !== '1.6') {
    return renderCycloneDx(as15(request));
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: { component: { type: 'application', name: request.name, version: request.version } },
    components: request.components.map(component16),
  };
}

export function validateCycloneDx16(doc: unknown): string[] {
  const errors: string[] = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['CycloneDX document must be an object'];
  }
  const root = doc as Record<string, unknown>;
  if (root.bomFormat !== 'CycloneDX') {
    errors.push('bomFormat must be "CycloneDX"');
  }
  if (root.specVersion !== '1.6') {
    errors.push('specVersion must be "1.6"');
  }
  if (!Array.isArray(root.components)) {
    errors.push('components must be an array');
  }
  return errors;
}
