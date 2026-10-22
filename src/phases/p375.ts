/**
 * Phase 375. Import maps and URL imports.
 * Off unless FULLSHIELD_EXPERIMENTAL_IMPORTMAP=1.
 * Does not fetch the URL.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_IMPORTMAP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface UrlImportFinding {
  ruleId: 'DEPS-URL-IMPORT-001';
  severity: 'medium' | 'high';
  specifier: string;
  message: string;
}

export interface SoundnessEvent {
  code: '271';
  message: string;
}

export interface ImportMapResult {
  findings: UrlImportFinding[];
  events: SoundnessEvent[];
}

function stripQuery(specifier: string): string {
  const query = specifier.indexOf('?');
  return query === -1 ? specifier : specifier.slice(0, query);
}

function classify(specifier: string, integrity: string | undefined): UrlImportFinding | null {
  const witness = stripQuery(specifier);
  if (specifier.startsWith('data:')) {
    return {
      ruleId: 'DEPS-URL-IMPORT-001',
      severity: 'high',
      specifier: witness,
      message: `Inline data URL import ${witness} is unsigned.`,
    };
  }
  if (specifier.startsWith('https:') && (integrity === undefined || integrity === '')) {
    return {
      ruleId: 'DEPS-URL-IMPORT-001',
      severity: 'medium',
      specifier: witness,
      message: `URL import ${witness} has no import-map integrity.`,
    };
  }
  return null;
}

function fromSource(source: string): UrlImportFinding[] {
  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: false, range: false, jsx: false });
  } catch {
    return [];
  }
  const findings: UrlImportFinding[] = [];
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      const spec = node.source?.value;
      if (typeof spec === 'string') {
        const hit = classify(spec, undefined);
        if (hit !== null) {
          findings.push(hit);
        }
      }
    }
    if (node.type === 'ImportExpression' && node.source.type === 'Literal' && typeof node.source.value === 'string') {
      const hit = classify(node.source.value, undefined);
      if (hit !== null) {
        findings.push(hit);
      }
    }
    const record = node as unknown as Record<string, unknown>;
    for (const value of Object.values(record)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'object' && item !== null && 'type' in item) {
            visit(item as TSESTree.Node);
          }
        }
      } else if (typeof value === 'object' && value !== null && 'type' in value) {
        visit(value as TSESTree.Node);
      }
    }
  };
  visit(ast);
  return findings;
}

export function urlImports(source: string, importMapJson: string | null): ImportMapResult {
  if (!enabled()) {
    return { findings: [], events: [] };
  }
  const findings = fromSource(source);
  const events: SoundnessEvent[] = [];
  if (importMapJson === null) {
    return { findings, events };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(importMapJson) as unknown;
  } catch {
    events.push({ code: '271', message: 'import map did not parse' });
    findings.push({
      ruleId: 'DEPS-URL-IMPORT-001',
      severity: 'medium',
      specifier: '<importmap>',
      message: 'The import map did not parse.',
    });
    return { findings, events };
  }
  if (typeof parsed !== 'object' || parsed === null) {
    events.push({ code: '271', message: 'import map did not parse' });
    findings.push({
      ruleId: 'DEPS-URL-IMPORT-001',
      severity: 'medium',
      specifier: '<importmap>',
      message: 'The import map did not parse.',
    });
    return { findings, events };
  }
  const imports = (parsed as { imports?: unknown }).imports;
  if (typeof imports !== 'object' || imports === null) {
    return { findings, events };
  }
  const integrity = (parsed as { integrity?: unknown }).integrity;
  const integrityMap = typeof integrity === 'object' && integrity !== null ? (integrity as Record<string, unknown>) : {};
  for (const [key, value] of Object.entries(imports as Record<string, unknown>)) {
    const targets = [key, value].filter((item): item is string => typeof item === 'string');
    for (const specifier of targets) {
      const integ = integrityMap[specifier];
      const hit = classify(specifier, typeof integ === 'string' ? integ : undefined);
      if (hit !== null) {
        findings.push(hit);
      }
    }
  }
  return { findings, events };
}
