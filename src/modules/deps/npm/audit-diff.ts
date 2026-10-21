export interface AuditScanFinding {
  ruleId?: string;
  references?: readonly string[];
}

export interface AuditDiff {
  onlyAudit: string[];
  onlyScan: string[];
  unmatched: string[];
}

/** Manifest fragment for a nested override. No lockfile body. */
export interface NestedOverrideFragment {
  overrides: Record<string, string>;
  pnpm: { overrides: Record<string, string> };
  resolutions: Record<string, string>;
  /** Printed beside the proposal. The lockfile is not edited. */
  notice?: 'run npm install';
}

const ADVISORY_PATTERNS = [/GHSA-[0-9a-z-]+/gi, /CVE-\d{4}-\d+/gi, /MAL-\d{4}-\d+/gi];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === 'string') {
    try {
      const parsed: unknown = JSON.parse(value);
      return asRecord(parsed);
    } catch {
      return undefined;
    }
  }
  return isRecord(value) ? value : undefined;
}

function remember(into: Map<string, string>, raw: string): void {
  const key = raw.toUpperCase();
  if (!into.has(key)) {into.set(key, raw);}
}

function collectIds(text: string, into: Map<string, string>): void {
  for (const pattern of ADVISORY_PATTERNS) {
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
    for (const match of text.matchAll(new RegExp(pattern.source, flags))) {
      const raw = match[0];
      if (raw !== undefined) {remember(into, raw);}
    }
  }
}

function collectFromValue(value: unknown, into: Map<string, string>): void {
  if (typeof value === 'string') {
    collectIds(value, into);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {collectFromValue(item, into);}
    return;
  }
  if (!isRecord(value)) {return;}
  for (const item of Object.values(value)) {collectFromValue(item, into);}
}

function hasVersion(entry: Record<string, unknown>): boolean {
  if (typeof entry.version === 'string' && entry.version.length > 0) {return true;}
  if (!Array.isArray(entry.findings)) {return false;}
  return entry.findings.some((finding) =>
    isRecord(finding) && typeof finding.version === 'string' && finding.version.length > 0);
}

function auditEntries(doc: Record<string, unknown>): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const key of ['vulnerabilities', 'advisories']) {
    const block = doc[key];
    if (!isRecord(block)) {continue;}
    for (const entry of Object.values(block)) {
      if (isRecord(entry)) {out.push(entry);}
    }
  }
  return out;
}

function isVulnRow(ruleId: string | undefined): boolean {
  if (ruleId === undefined || ruleId.length === 0) {return true;}
  return ruleId.includes('VULN');
}

function sortedValues(ids: Map<string, string>, skip?: Map<string, string>): string[] {
  const values: string[] = [];
  for (const [key, display] of ids) {
    if (skip?.has(key) === true) {continue;}
    values.push(display);
  }
  values.sort((a, b) => a.localeCompare(b));
  return values;
}

/**
 * Phase 250. Ids only in the audit file, ids only in the scan, and audit ids
 * that have no version. Does not invent ids and does not read the filesystem.
 */
export function auditDiff(auditJson: unknown, scanFindings: readonly AuditScanFinding[]): AuditDiff {
  const doc = asRecord(auditJson);
  const versioned = new Map<string, string>();
  const bare = new Map<string, string>();
  if (doc !== undefined) {
    for (const entry of auditEntries(doc)) {
      const found = new Map<string, string>();
      collectFromValue(entry, found);
      const dest = hasVersion(entry) ? versioned : bare;
      for (const [key, display] of found) {
        if (versioned.has(key)) {continue;}
        remember(dest, display);
      }
    }
  }
  for (const key of versioned.keys()) {bare.delete(key);}

  const scan = new Map<string, string>();
  for (const finding of scanFindings) {
    if (!isVulnRow(finding.ruleId)) {continue;}
    for (const reference of finding.references ?? []) {collectIds(reference, scan);}
  }

  return {
    onlyAudit: sortedValues(versioned, scan),
    onlyScan: sortedValues(scan, versioned),
    unmatched: sortedValues(bare),
  };
}

/**
 * Phase 248. Nested npm override key `parent>child`, plus pnpm.overrides and yarn resolutions.
 * An empty parent is a direct same-major proposal and does not add a nested key.
 * No version means no proposal. This does not edit a lockfile.
 */
export function nestedOverrideKey(
  parent: string,
  child: string,
  version: string | undefined,
): NestedOverrideFragment | undefined {
  if (version === undefined || version.length === 0) {return undefined;}
  const key = parent.length === 0 ? child : `${parent}>${child}`;
  const fragment: NestedOverrideFragment = {
    overrides: { [key]: version },
    pnpm: { overrides: { [key]: version } },
    resolutions: { [key]: version },
  };
  if (parent.length > 0) {fragment.notice = 'run npm install';}
  return fragment;
}
