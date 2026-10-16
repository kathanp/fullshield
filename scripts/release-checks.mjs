/**
 * Pure checks for Phase 36. CLI wrappers live in semver-check, pack-budget,
 * and provenance-gate. No network.
 */

export function parseVersion(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(String(value));
  if (!match) throw new Error(`not a version: ${value}`);
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

export function bumpKind(fromVersion, toVersion) {
  const from = parseVersion(fromVersion);
  const to = parseVersion(toVersion);
  if (to.major !== from.major) return to.major > from.major ? 'major' : 'decrease';
  if (to.minor !== from.minor) return to.minor > from.minor ? 'minor' : 'decrease';
  if (to.patch !== from.patch) return to.patch > from.patch ? 'patch' : 'decrease';
  return 'none';
}

/**
 * @param {{ newRuleIds?: string[], newCommands?: string[], newFlags?: string[], newExports?: string[], stableChanged?: boolean }} signals
 */
export function requiredBump(signals) {
  const feature =
    (signals.newRuleIds?.length ?? 0) > 0 ||
    (signals.newCommands?.length ?? 0) > 0 ||
    (signals.newFlags?.length ?? 0) > 0 ||
    (signals.newExports?.length ?? 0) > 0 ||
    signals.stableChanged === true;
  return feature ? 'minor' : 'patch';
}

const RANK = { none: 0, patch: 1, minor: 2, major: 3, decrease: -1 };

export function bumpSatisfies(actual, required) {
  return (RANK[actual] ?? -1) >= (RANK[required] ?? 99);
}

export const PACK_UNPACKED_MAX = 2 * 1024 * 1024;
export const PACK_FILES_MAX = 120;

/**
 * @param {{ unpackedBytes: number, fileCount: number, hardDeps: string[], previousHardDeps: string[] }} pack
 * @returns {string[]}
 */
export function packBudgetErrors(pack) {
  const errors = [];
  if (pack.unpackedBytes > PACK_UNPACKED_MAX) {
    errors.push(`unpacked ${pack.unpackedBytes} bytes exceeds ${PACK_UNPACKED_MAX}`);
  }
  if (pack.fileCount > PACK_FILES_MAX) {
    errors.push(`file count ${pack.fileCount} exceeds ${PACK_FILES_MAX}`);
  }
  const prev = new Set(pack.previousHardDeps);
  for (const dep of pack.hardDeps) {
    if (!prev.has(dep)) errors.push(`new hard dependency ${dep}`);
  }
  return errors;
}

export function attestationsPresent(packument) {
  const attestations = packument?.dist?.attestations;
  if (attestations == null) return false;
  if (typeof attestations === 'object' && Object.keys(attestations).length === 0) return false;
  if (attestations === '') return false;
  return true;
}

/** @param {string[]} before @param {string[]} after */
export function addedLines(before, after) {
  const prior = new Set(before);
  return after.filter((line) => !prior.has(line));
}

function ruleFile(key) {
  const [ruleId, file] = key.split('\t');
  return `${ruleId}\t${file}`;
}

/**
 * Diff finding keys `ruleId\\tfile\\tline\\tseverity`.
 * A key with the same rule and file but a different line or severity is `changed`.
 * @param {string[]} baseKeys
 * @param {string[]} headKeys
 */
export function diffFindingKeys(baseKeys, headKeys) {
  const baseSet = new Set(baseKeys);
  const headSet = new Set(headKeys);
  const removed = baseKeys.filter((key) => !headSet.has(key));
  const added = headKeys.filter((key) => !baseSet.has(key));
  const removedByRuleFile = new Map();
  for (const key of removed) {
    const id = ruleFile(key);
    const list = removedByRuleFile.get(id) ?? [];
    list.push(key);
    removedByRuleFile.set(id, list);
  }
  const changed = [];
  const addedOnly = [];
  for (const key of added) {
    const list = removedByRuleFile.get(ruleFile(key));
    if (list !== undefined && list.length > 0) changed.push({ from: list.shift(), to: key });
    else addedOnly.push(key);
  }
  const removedOnly = [];
  for (const list of removedByRuleFile.values()) removedOnly.push(...list);
  return { added: addedOnly, removed: removedOnly, changed };
}

/** @param {string} actual @param {string} approved */
export function approvedDiffMatches(actual, approved) {
  return actual.trim() === approved.trim();
}

/**
 * @param {Array<{ app: string, added: string[], removed: string[], changed: Array<{ from: string, to: string }> }>} apps
 */
export function formatSnapshotDiff(apps) {
  const lines = [];
  for (const app of apps) {
    const drift = app.added.length + app.removed.length + app.changed.length > 0;
    lines.push(`${drift ? 'DRIFT' : 'IDENTICAL'} ${app.app}`);
    for (const row of app.removed) lines.push(`- ${row}`);
    for (const row of app.added) lines.push(`+ ${row}`);
    for (const row of app.changed) lines.push(`~ ${row.from} -> ${row.to}`);
  }
  return `${lines.join('\n')}\n`;
}
