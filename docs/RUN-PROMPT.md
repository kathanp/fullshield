# Run prompt

This file is the only run prompt. A later chat says: `Read docs/RUN-PROMPT.md and run Batch N`.

## DONE

- STEP F (CASE A). Provenance commit `91bbc6bb2b8e8fb46805e872a47952c3bd4a0907` is tag `v0.3.0` and `origin/main`.
- R1. `restore-0.3.0` merged. Proof 1: dist matches the npm tarball except `dist/cli/index.js`, `dist/index.js`, and `dist/index.d.ts` (Phase 46 floor and Phase 47 console). Proof 2: vulnerable-app 35, clean-app 0, nodegoat 256, juice-shop 105, dvna 23, goof 271, vulnerable-node 61.
- R2. `restore-0.4.0` merged. vulnerable-node 61 → 63. New keys: `SAST-NOSQLI-001` at `routes/shop.js:41` and `:58`, both high. Version stayed 0.3.0.
- M. Phase 47 grouped rows recorded. nodegoat 36, juice-shop 49, dvna 14, goof 63, vulnerable-node 41. No row-count threshold.
- Phase 48. Unused direct dependencies. Merged. default-scan-diff EMPTY.

## RESUME 2 (Kathan, 2026-10-18)

Replaces all earlier run prompts. Read `SECURITY_SCANNER_SPEC.md` (rev 2026-10-18b, Sections 36–37, decisions D1–D4), `PROGRESS.md`, and `docs/RUN-LOG.md` first.

### Human decisions

Record each in spec Section 30 and in `PROGRESS.md`.

- D6: 0.3.0 is published on npm and was approved. That is known. It is not a stop condition. The job was to make git match it. DONE.
- D7: Restoring the exact 0.3.0 source onto next was approved, including the default-scan change from 0.2.6 (R10), because the R1 checks passed. The unpublished Mongo-filter change was approved the same way.
- D8: `package.json` and README on next are 0.3.0. That is the version npm already has. Do not bump past 0.3.0. 0.4.0 is the human's to set at release.

### Never

- Never run `git stash drop`, `git stash clear`, or `git stash pop`.
- Never delete branch `backup/stash-2026-10-18` (`31bf17a`) or the iCloud patch file.
- Never push `backup/stash-2026-10-18`.
- Never tag, publish, or merge to main.
- Push `next` only when the human asks.
- Never set `reviewed: true`. Never fill a label, reviewer, or note cell. Never scan an untouched holdout (`verademo-javascript`, `serverless-goat`, `mongection`).
- Never edit `ground-truth.json`, `triage.json`, `expected-findings.json`, or an existing test to make a check pass. Never weaken a phase 46 or 47 test.
- No new hard dependencies. Optional peers only, lazy-loaded.
- Every new rule ID gets `rules/<ID>.md`, a positive and a negative fixture, a compliance-map row, and a mutation-smoke target.
- Every new CLI error path gets an `FS-E` code in `docs/errors.md` and `src/cli/errors.ts`.
- Do not invent thresholds or new stop conditions. Published versions on npm are not a stop (D6).
- Skip phase 56 until the human amends R15 with hosts. Write no code for it.
- Do not put `SUPPLY-SECHOLDER-001` or `SUPPLY-STEALER-001` string literals in `src` until the compliance map has rows.

### STEP P

Each phase:

- branch `phase-N` off the current `next`
- failing test first
- verify green on Node 22 and 24
- default-scan-diff EMPTY, except PARK-AT-DIFF phases
- one commit, `phase-N: <summary>`
- merge into `next`
- update `PROGRESS.md` and `docs/RUN-LOG.md`

PARK, don't halt. A failed acceptance, an unapproved stable diff, a needed test or fixture or ground-truth edit, or a coverage margin under 2 points means: commit the branch, add an entry to `docs/PARKED.md` (phase, branch, reason, what you need, files to open), and continue.

STOP the whole run ONLY for:

- the same failure twice in a row on `next`
- `next` failing verify when you cannot fix it without editing a test or fixture
- an action that needs the human: push, tag, publish, a version change beyond D8, merge to main, `reviewed: true`, promoting a flag

### Known flake

- If the only failure in verify is the RASP p95 latency test, re-run that single test up to 2 times. If it passes, record "RASP p95 flake" in `docs/RUN-LOG.md` and continue. That is not a failure under the stop rules.
- If it fails all 3 runs, PARK the current phase with the timings.
- Never change the 1 ms budget.

### Batches

Run one batch per chat. At the end of a batch, give the END OF RUN report and stop. If a batch finishes with context to spare, start the next batch. Stop at the end of Batch 2 no matter what.

| Batch | Phases, in order | Theme |
|---|---|---|
| 1 | 49, 61, 60, 66 | Dependency fixes you can act on: upgrade plan, evidence, explain, SBOM |
| 2 | 70, 62, 63, 54 | Supply-chain checks: malware heuristics, lockfile diff, lockfile formats, workspaces |
| 3 | 64, 53, 65, 74 | Taint precision and SARIF |
| 4 | 55, 71, 72 | Runtime: observed reachability, RASP sinks, DNS pins |
| 5 | 57, 58, 69, 67, 68, 59, 73 | Custom rules, route map, playbooks, review tooling, Action, promotion report |
| 6 | 75, 50, 51, 52 | Stable-output changes: PARK-AT-DIFF only, never merge |

Skip 56.

Phase 66 needs Phase 61. Phase 65 must stay byte-identical; a speed versus accuracy tradeoff means PARK. SAFE-WITHOUT-RESTORE phases are 60, 70, 55, 71, 72, 69, 67, 68, 59. The 0.3.0 restore was not parked, so every batch phase runs.

### End of a batch

1. Which batch finished, and which CASE / proofs still stand (do not re-run STEP F).
2. A table: step/phase | branch | merged/parked/skipped | flag | tests added | default-scan-diff
3. `docs/PARKED.md` copied in full
4. verify on `next`, Node 22 and Node 24, for the phases in the batch
5. Anything the next chat must not redo

## ADDENDUM (Kathan, 2026-10-18)

Read it together with RESUME 2 above.

Docs reconcile is its own branch, `docs-reconcile`, before Batch 1. Files: `docs/errors.md`, `docs/NOISE-REPORT.md`, `docs/NODE-20.md`, `docs/STABILIZATION-PLAN.md`, `docs/demo.md`, `bench/REVIEW.md`, `rules/README.md`, `CONTRIBUTING.md`. Diff `backup/stash-2026-10-18` against `next`. Bring over only text that is still true. Every `FS-E` code in `src/cli/errors.ts` must appear in `docs/errors.md`. Never change the version (D8). Leave the stash copies of `package.json`, `package-lock.json`, `CHANGELOG.md`, `README.md`, and `SECURITY_SCANNER_SPEC.md` alone. Merge with an empty default-scan-diff.
