# Noise report

Historical. This report explains the pre-grouping snapshot from 0.2.x (NodeGoat 379, goof 354). Grouping shipped in 0.3.0 (NodeGoat 256, goof 271 in JSON). The console fold shipped in 0.4.0. Current counts are in `BENCHMARK.md`. `"reviewed"` is still false. This is not a precision or recall claim.

Counts below are from `bench/snapshots/HEAD.json` before the grouping change. That file was the default `scan --json --offline-safe` snapshot at the time of the report. In-scope ground truth on those apps is 7 and 11 entries.

`scripts/noise-report.mjs` re-runs that scan on the five pinned tuning/seen apps and prints `app | module | ruleId | severity | count`. Untouched holdouts are not scanned.

## Where the 379 and 354 come from

| app | DEPS-VULN-001 | other deps | sast | secrets | config | total |
|---|---|---|---|---|---|---|
| nodegoat | 319 | 39 deprecated | 3 | 2 | 16 | 379 |
| goof | 315 | 21 deprecated | 6 | 2 | 10 | 354 |

On NodeGoat, 299 of the vuln findings sit on `package-lock.json` and 20 on `package.json`. A saved full report (`benchmarks/results/nodegoat-phase24.json`, 319 `DEPS-VULN-001`) has 84 package names and **zero** duplicate package-version + advisory pairs. lodash alone is 30 findings across five versions (`2.4.2`, `4.13.1`, `4.17.11`, `4.17.20`, `4.17.21`) because the same GHSA matches more than one installed version. 219 are `not-imported`, 129 are marked dev-only, 84 are reachable via a dependency, 12 are directly reachable.

So the count is not one finding per transitive path. The lockfile parser already dedupes `name@version`. The inflation is one finding per installed version per advisory.

No snapshot key is under `node_modules`, `dist`, `build`, `.next`, `coverage`, `vendor`, or `*.min.js`. Juice Shop's `CONFIG-DIRLIST-001` hits are in `server.ts` and `data/static/codefixes/`, which is challenge-copy source, not a vendored directory.

## Top 10 rules by count

Counts are summed across vulnerable-app, clean-app, nodegoat, juice-shop, dvna, goof, and vulnerable-node in that snapshot.

1. **DEPS-VULN-001 — 658.** Hypothesis: one row per vulnerable installed version per advisory, including not-imported and dev-only copies. Grouping by package name + advisory (not by path, and not by deleting the rule) is the reduction that matches the data. Severity stays the highest in the group.
2. **DEPS-DEPRECATED-001 — 60.** Hypothesis: the lockfile `deprecated` field, one row per package version. Not the same as a vuln advisory. The rule stays.
3. **CONFIG-DIRLIST-001 — 33.** Hypothesis: Juice Shop `express.static` without an index restriction, repeated in `server.ts` and in `data/static/codefixes/*` solution copies. The copies are different files and lines, so sink-line dedupe does not merge them. Those copies stay; the README already says they are not special-cased.
4. **SAST-NOSQLI-001 — 22.** Hypothesis: real NoSQL sinks plus challenge copies on different lines. Same rule + same line would be one finding; different lines stay.
5. **SAST-XSS-001 — 18.** Hypothesis: template interpolations. DVNA `views/app/products.ejs` has six hits on one file at different lines. That is multiple sinks, not one sink repeated.
6. **CONFIG-HELMET-001 — 16.** Hypothesis: an Express app file that never calls `helmet`, once per entry file that looks like a server. Not a duplicate path.
7. **CONFIG-RATELIMIT-001 — 16.** Hypothesis: auth-looking routes without a rate limiter, one per route. Not the same sink line.
8. **SAST-PATH-001 — 13.** Hypothesis: `path.join` / `readFile` of request input. Distinct lines.
9. **SAST-SQLI-001 — 12.** Hypothesis: query string concatenation. Distinct lines. Cross-file traces can land on the same sink as an intra-file hit; those two should collapse.
10. **SAST-AUTH-001 — 11.** Hypothesis: routes without auth middleware, low severity, one per route. Not removed.

No rule was changed to produce this report.
