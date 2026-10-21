/**
 * Well-known npm package names used for typosquat detection (Levenshtein ≤ 1).
 * Names are loaded from models/npm-popular.json in list order. This module does
 * not fetch names and does not add, drop, or reorder them.
 */
import entries from '../../../models/npm-popular.json' with { type: 'json' };

export const POPULAR_PACKAGES: readonly string[] = entries.map((entry) => entry.name);
