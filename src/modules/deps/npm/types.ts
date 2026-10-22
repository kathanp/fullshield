import { makeFindingId, type Confidence, type Finding, type ModuleName, type Severity } from '../../../core/finding.js';
import { groupForPhaseFlag } from './groups.js';

/** Plain compliance row. `src/compliance/index.ts` spreads these into `RULE_MAP`. */
export interface NpmDepthRow {
  ruleId: string;
  owasp: string;
  cwe: string;
  asvs: string;
  pci: string;
}

/** One scan's npm inputs. Built once and passed to every 108–250 check. */
export interface NpmFacts {
  cwd: string;
  files: readonly string[];
  manifestRaw?: string;
  lockTexts: Readonly<Record<string, string>>;
  cacheDir: string;
  offline: boolean;
  manifest?: Record<string, unknown>;
  /** Project `.npmrc` text keyed by the relative path listed in the scan. */
  npmrcFiles: ReadonlyMap<string, string>;
  homeNpmrc?: string;
  lockRows: readonly NpmLockRow[];
  names: readonly string[];
  graph: readonly NpmGraphNode[];
  /** Lifecycle and manifest script bodies, keyed by `source:name`. */
  scriptText: ReadonlyMap<string, string>;
  /** Raw registry-cache JSON, one entry per package name. */
  packuments: ReadonlyMap<string, unknown>;
  /** Raw tarball descriptor JSON, one entry per package name. */
  tarballs: ReadonlyMap<string, unknown>;
  /** Tarball bytes keyed by integrity string and by registry URL. */
  tarballBytes: ReadonlyMap<string, Buffer>;
}

export interface NpmLockRow {
  path: string;
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  deps: readonly string[];
}

export interface NpmGraphNode {
  path: string;
  name: string;
  version?: string;
  deps: readonly string[];
}

export interface NpmDepthInput {
  cwd: string;
  /** Posix-style relative paths. */
  files: readonly string[];
  manifestRaw?: string;
  /** Filename → file text for lockfiles that exist in `files`. */
  lockTexts: Readonly<Record<string, string>>;
  /** Absolute cache directory. `--offline` reads this and does not fetch. */
  cacheDir: string;
  offline: boolean;
  /** Present when this scan already built `NpmFacts`. Lanes read it instead of refetching. */
  facts?: NpmFacts;
  /**
   * Test and caller hook. When set and `offline` is false, each missing packument
   * and each registry tarball is requested through this function at most once.
   * Production scans omit it and stay on the cache, as phases 108–250 do today.
   */
  fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>;
}

/**
 * Per-phase flags are aliases of their group flag (phase 261). Either env value
 * `1` enables the check. The eight group names live in `groups.ts`.
 */
export function npmFlag(name: string): boolean {
  if (process.env[`FULLSHIELD_EXPERIMENTAL_${name}`] === '1') {return true;}
  const group = groupForPhaseFlag(name);
  return group !== undefined && process.env[`FULLSHIELD_EXPERIMENTAL_${group}`] === '1';
}

export function npmRow(ruleId: string, cwe: string): NpmDepthRow {
  return {
    ruleId,
    owasp: 'A06:2021 Vulnerable Components',
    cwe,
    asvs: 'V14.2.1',
    pci: 'PCI DSS 6.3.3',
  };
}

export function npmFinding(
  ruleId: string,
  severity: Severity,
  file: string,
  snippet: string,
  title: string,
  message: string,
  remediation: string,
  confidence: Confidence = 'high',
  module: ModuleName = 'deps',
): Finding {
  return {
    id: makeFindingId(ruleId, file, snippet),
    ruleId,
    module,
    title,
    severity,
    confidence,
    file,
    snippet,
    message,
    remediation,
  };
}
