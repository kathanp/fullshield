# FullShield stabilization plan

This note's phases 1–6 are already in 0.3.0 and later. It is not the build queue. The queue is `SECURITY_SCANNER_SPEC.md` Section 36. Phase 5 below added Node 20. That support was removed in spec Phase 46 because Node 20 reached end of life in April 2026. The package enforces Node >= 22.13.

Cursor can’t measure precision. It can build the review tooling, but a human has to decide which findings are real. If Cursor labels its own findings, the numbers mean nothing.

Paste this first as the project rules, in `.cursor/rules` or at the top of each chat:

## FullShield project rules (apply to every task)

1. NO new features or new experimental flags until told otherwise.
2. Never edit `bench/*/ground-truth.json` or triage files to improve scores.
3. Never mark anything `"reviewed": true`. Only a human does that.
4. Any change to default `scan` output must:
   - regenerate `bench/snapshots/HEAD.json`
   - show the diff in `bench/snapshots/DIFF.txt`
   - add a CHANGELOG entry under "Default scan changes"
5. All tests must pass on the full matrix (Linux/macOS/Windows x Node 22/24).
6. Keep README honest: no recall/precision claims without reviewed data.
7. Small commits, one concern per commit. Explain each change in the commit message.
8. If a fix needs a tradeoff (speed vs accuracy), stop and ask me first.

## Phase 1: Noise audit

Start here because it decides everything after it.

Task: Find out why default scan produces 379 findings on NodeGoat and 354 on goof when ground truth has ~7-11 in-scope bugs.

1. Write `scripts/noise-report.mjs` that runs default `scan --json --offline-safe` on every pinned bench app and outputs a table:
   app | module (deps/sast/secrets/config) | ruleId | severity | count
2. Flag likely noise sources:
   - same rule firing many times on one file or one sink
   - deps findings repeated per transitive path instead of per package
   - findings inside node_modules, vendored, minified, test, or fixture files
3. Write `docs/NOISE-REPORT.md` with the top 10 rules by count and a hypothesis for each (do NOT change any rule yet).
4. Stop and show me the report before fixing anything.

## Phase 2: Fix the noise

Run this only after you’ve read the report.

Task: Reduce duplicate/low-value findings found in `docs/NOISE-REPORT.md`.

Allowed changes:

- Group deps findings: one finding per vulnerable package+advisory, with all dependency paths listed inside it (not one finding per path).
- Dedupe SAST findings with the same ruleId + sink line.
- Default-exclude node_modules, dist, build, .next, coverage, minified (`*.min.js`), and vendored dirs; make it configurable.

Not allowed:

- Removing a rule or lowering severity just to cut the count.
- Changing ground truth.

Acceptance:

- In-scope matches on NodeGoat/Juice Shop/DVNA/goof/vulnerable-node do not drop.
- Total finding count per app is reported before vs after in CHANGELOG.

## Phase 3: Next.js out-of-memory crash

Task: `node bench/perf.mjs --measure` aborts on next.js with JavaScript heap out of memory (peak ~1.7 GB). Make it finish.

Investigate in this order:

1. Are generated/vendored/compiled files being parsed? Skip them by default.
2. Add a max file size for SAST parsing (configurable, default e.g. 1 MB); report skipped files as info, never silently.
3. Release ASTs after each file; check for caches that grow unbounded (taint maps, symbol tables) and add LRU caps.
4. Parse pool: cap workers and per-worker memory.

Acceptance:

- next.js scan completes with peak memory under 1 GB on 5/5 runs.
- nest and undici do not get slower.
- Results recorded in `bench/perf-baseline.json`.
- In-scope bench matches unchanged.

## Phase 4: Precision review tooling

Cursor builds the tooling and you do the labeling.

Task: Build tooling so a HUMAN can measure real-world precision.

1. `scripts/sample-findings.mjs`: for each repo in `bench/realworld.json`, randomly sample up to 30 findings (fixed seed), stratified by module.
2. Output `bench/review/<repo>.csv` with columns:
   id, ruleId, severity, file, line, code snippet (5 lines), message, label (blank), reviewer (blank), note (blank)
   label values allowed: TP, FP, unsure
3. `scripts/precision.mjs` reads labeled CSVs and prints precision per module and per rule, ignoring blank labels, and counting "unsure" separately.
4. Do NOT fill in any labels yourself.

## Phase 5: Node 20 support

Task: Check if FullShield can support Node 20.

1. List every API that requires Node >= 22.13 (`node:sqlite`, others).
2. If `node:sqlite` is only used by history/confirm, make those features print a clear message on Node 20 ("requires Node 22.13+") instead of blocking the whole package.
3. Add Node 20 to the CI matrix.
4. Update `package.json` engines and README only if all tests pass.
5. Stop and report if anything else blocks Node 20.

## Phase 6: Comparison against Semgrep and osv-scanner

Task: Fix `COMPARISON.md` so mapped class buckets aren't empty.

1. Map Semgrep rule IDs and osv-scanner results to FullShield classes (SQLI, CMDI, PATH, SSRF, XSS, DEPS, SECRETS...). Put the mapping in a reviewable JSON file.
2. Re-run on the same pinned apps; for apps without lockfiles, note it.
3. Report per class: found by FullShield only / Semgrep only / both / neither, matched by class + file + line ±3 against existing ground truth.
4. Keep the "not reviewed, not a recall claim" label.
