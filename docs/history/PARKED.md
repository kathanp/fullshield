# Parked work

Nothing is parked. The stash had no files that were neither 0.3.0 source, the NoSQL filter, nor docs.

## Stash files not applied

These are the docs-only hunks on `stash@{0}` (WIP on feat/advanced). The code they describe is already on `next` from the 0.3.0 restore, phases 46 and 47, or the NoSQL restore. `package.json` in the stash sets 0.4.0; D8 keeps 0.3.0.

- `.gitignore` — docs
- `BENCHMARK.md` — docs
- `CHANGELOG.md` — docs (next has its own Unreleased note)
- `COMPARISON.md` — docs
- `CONTRIBUTING.md` — docs
- `PROGRESS.md` — docs
- `README.md` — docs
- `RELEASING.md` — docs
- `SECURITY.md` — docs
- `SECURITY_SCANNER_SPEC.md` — docs
- `bench/REVIEW.md` — docs
- `bench/snapshots/0.3.0.json` — measurement, regenerated on next
- `bench/snapshots/DIFF.txt` — measurement, regenerated on next
- `bench/snapshots/HEAD.json` — measurement
- `benchmarks/AI-REPORT.md` — docs
- `benchmarks/REPORT.md` — docs
- `benchmarks/SELF-SCAN.md` — docs
- `docs/ADVANCED-SPEC.md` — docs (stash deletes it)
- `docs/NODE-20.md` — docs
- `docs/NOISE-REPORT.md` — docs
- `docs/STABILIZATION-PLAN.md` — docs
- `docs/demo.md` — docs
- `docs/errors.md` — docs
- `package-lock.json` — version metadata
- `package.json` — would set 0.4.0; left at 0.3.0 (D8)
- `rules/README.md` — docs
