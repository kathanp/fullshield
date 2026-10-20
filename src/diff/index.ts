import { lineIndependentFingerprint } from '../core/fingerprint.js';
import { isSeverity, meetsThreshold, type Finding, type Severity } from '../core/finding.js';
import { DIFF_FLAG } from '../modules/sast/experimental.js';

export { DIFF_FLAG };

export type DiffFinding = Finding;

export interface ScanDiff {
  unchanged: DiffFinding[];
  added: DiffFinding[];
  removed: DiffFinding[];
  moved: Array<{ before: DiffFinding; after: DiffFinding }>;
}

function posix(file: string | undefined): string {
  return (file ?? '').replace(/\\/g, '/');
}

export function diffKey(
  finding: Pick<DiffFinding, 'ruleId' | 'file' | 'severity' | 'snippet' | 'message'>,
): string {
  return lineIndependentFingerprint(finding);
}

function groupById(findings: readonly DiffFinding[]): Map<string, DiffFinding[]> {
  const groups = new Map<string, DiffFinding[]>();
  for (const finding of findings) {
    if (finding.id === undefined || finding.id.length === 0) {continue;}
    const list = groups.get(finding.id) ?? [];
    list.push(finding);
    groups.set(finding.id, list);
  }
  return groups;
}

/**
 * Pair a move only when one removed finding and one added finding share an id.
 * Duplicate ids on either side stay added or removed.
 */
function pairMoves(
  removed: readonly DiffFinding[],
  added: readonly DiffFinding[],
): Array<{ before: DiffFinding; after: DiffFinding }> {
  const removedIds = groupById(removed);
  const addedIds = groupById(added);
  const moved: Array<{ before: DiffFinding; after: DiffFinding }> = [];
  for (const [id, group] of removedIds) {
    const match = addedIds.get(id);
    if (group.length === 1 && match?.length === 1 && group[0] !== undefined && match[0] !== undefined) {
      moved.push({ before: group[0], after: match[0] });
    }
  }
  return moved;
}

function byLocation(a: DiffFinding, b: DiffFinding): number {
  return (
    (a.line ?? 0) - (b.line ?? 0) ||
    a.id.localeCompare(b.id) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

function groupFindings(findings: readonly DiffFinding[]): Map<string, DiffFinding[]> {
  const groups = new Map<string, DiffFinding[]>();
  for (const finding of findings) {
    const key = diffKey(finding);
    const list = groups.get(key) ?? [];
    list.push(finding);
    groups.set(key, list);
  }
  return groups;
}

/** Compare two finding lists. Does not invent findings. */
export function diffScans(before: readonly DiffFinding[], after: readonly DiffFinding[]): ScanDiff {
  const beforeGroups = groupFindings(before);
  const afterGroups = groupFindings(after);
  const unchanged: DiffFinding[] = [];
  const added: DiffFinding[] = [];
  const removed: DiffFinding[] = [];
  const moved: Array<{ before: DiffFinding; after: DiffFinding }> = [];
  const keys: string[] = [];
  for (const key of beforeGroups.keys()) {keys.push(key);}
  for (const key of afterGroups.keys()) {
    if (!beforeGroups.has(key)) {keys.push(key);}
  }

  for (const key of keys) {
    const left = [...(beforeGroups.get(key) ?? [])].sort(byLocation);
    const right = [...(afterGroups.get(key) ?? [])].sort(byLocation);
    const paired = Math.min(left.length, right.length);
    for (let i = 0; i < paired; i += 1) {
      const earlier = left[i];
      const later = right[i];
      if (earlier === undefined || later === undefined) {continue;}
      if ((earlier.line ?? 0) === (later.line ?? 0)) {unchanged.push(later);}
      else {moved.push({ before: earlier, after: later });}
    }
    for (const finding of left.slice(paired)) {removed.push(finding);}
    for (const finding of right.slice(paired)) {added.push(finding);}
  }

  const idMoves = pairMoves(removed, added);
  const movedBefore = new Set(idMoves.map((item) => item.before));
  const movedAfter = new Set(idMoves.map((item) => item.after));
  return {
    unchanged,
    added: added.filter((finding) => !movedAfter.has(finding)),
    removed: removed.filter((finding) => !movedBefore.has(finding)),
    moved: [...moved, ...idMoves],
  };
}

export function parseScanDocument(text: string): DiffFinding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error('scan JSON must be an object with a findings array or a findings array');
  }
  const list = Array.isArray(parsed)
    ? parsed
    : typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { findings?: unknown }).findings)
      ? (parsed as { findings: unknown[] }).findings
      : undefined;
  if (list === undefined) {
    throw new Error('scan JSON must be an object with a findings array or a findings array');
  }
  return list.map((item) => {
    if (typeof item !== 'object' || item === null) {
      throw new Error('scan JSON finding is missing ruleId or severity');
    }
    const record = item as Record<string, unknown>;
    const ruleId = record.ruleId;
    const severity = record.severity;
    if (typeof ruleId !== 'string' || ruleId.length === 0 || typeof severity !== 'string') {
      throw new Error('scan JSON finding is missing ruleId or severity');
    }
    if (!isSeverity(severity)) {
      throw new Error(`scan JSON finding has an unknown severity "${severity}"`);
    }
    if (record.line !== undefined && (typeof record.line !== 'number' || !Number.isInteger(record.line) || record.line < 0)) {
      throw new Error('scan JSON finding line must be an integer >= 0');
    }
    return item as DiffFinding;
  });
}

export function addedFails(diff: ScanDiff, failOn: Severity): boolean {
  return diff.added.some((finding) => finding.source !== 'ai' && meetsThreshold(finding.severity, failOn));
}

const ADDED_CAP = 20;

function addedLine(finding: DiffFinding): string {
  const where = finding.file !== undefined ? ` ${posix(finding.file)}:${finding.line ?? 0}` : '';
  return `${finding.severity} ${finding.ruleId}${where}`;
}

/** Human summary. Lists at most 20 added findings. */
export function renderDiffText(diff: ScanDiff): string {
  const lines = [
    `fullshield diff: unchanged ${diff.unchanged.length}, added ${diff.added.length}, removed ${diff.removed.length}, moved ${diff.moved.length}`,
  ];
  if (diff.added.length === 0) {return lines.join('\n');}
  lines.push('added:');
  for (const finding of diff.added.slice(0, ADDED_CAP)) {lines.push(addedLine(finding));}
  if (diff.added.length > ADDED_CAP) {lines.push(`${diff.added.length - ADDED_CAP} more — use --json`);}
  return lines.join('\n');
}
