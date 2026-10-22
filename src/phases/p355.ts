/**
 * Phase 355. Local malware-shaped signatures.
 * Off unless FULLSHIELD_EXPERIMENTAL_MALSIG=1.
 * Unreviewed shapes are info. The message names the shape id. No network.
 */

import { interpretScript } from './p353.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MALSIG';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface MalwareShape {
  id: string;
  source: string;
  reviewed: boolean;
  fp: string;
  parts: readonly ('read-npmrc' | 'build-url')[];
  fixtureUrl?: string;
}

export const NPMRC_URL_SHAPE: MalwareShape = {
  id: 'npmrc-plus-url',
  source: 'phase 355 example: install script reads .npmrc and builds a URL',
  reviewed: false,
  fp: 'A legitimate script may read npm config and post a log line to an internal host.',
  parts: ['read-npmrc', 'build-url'],
  fixtureUrl: 'https://example.invalid/collect',
};

export interface ShapeFinding {
  ruleId: 'DEPS-MALSIG-001';
  severity: 'info' | 'high';
  message: string;
  shapeId: string;
}

export function validateShape(shape: MalwareShape): string[] {
  const errors: string[] = [];
  if (shape.fixtureUrl !== undefined) {
    try {
      const host = new URL(shape.fixtureUrl).hostname;
      if (host !== 'example.invalid') {
        errors.push('fixture-url');
      }
    } catch {
      errors.push('fixture-url');
    }
  }
  if (shape.reviewed && shape.fp.trim().length === 0) {
    errors.push('fp');
  }
  if (shape.source.trim().length === 0) {
    errors.push('source');
  }
  return errors;
}

export function shapeFindings(source: string, shapes: readonly MalwareShape[], path = 'scripts/install.js'): ShapeFinding[] {
  if (!enabled()) {
    return [];
  }
  const abstract = interpretScript(source, path);
  const findings: ShapeFinding[] = [];
  for (const shape of shapes) {
    if (validateShape(shape).length > 0) {
      continue;
    }
    const needsUrl = shape.parts.includes('build-url');
    const needsNpmrc = shape.parts.includes('read-npmrc');
    const hasUrl = abstract.hosts.length > 0;
    if (needsNpmrc && !abstract.readsNpmrc) {
      continue;
    }
    if (needsUrl && !hasUrl) {
      continue;
    }
    if (needsNpmrc && needsUrl && !(abstract.readsNpmrc && hasUrl)) {
      continue;
    }
    findings.push({
      ruleId: 'DEPS-MALSIG-001',
      severity: shape.reviewed ? 'high' : 'info',
      shapeId: shape.id,
      message: `Shape ${shape.id} matched. The match is not a named campaign.`,
    });
  }
  return findings;
}

export function reviewShapeGuard(commit: { automation: boolean; reviewed: boolean }): void {
  if (commit.automation && commit.reviewed) {
    throw new Error('only a human commit may set reviewed');
  }
}
