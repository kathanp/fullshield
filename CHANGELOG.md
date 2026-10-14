# Changelog

All notable changes to FullShield are documented here.

## Unreleased — harden-1

- `fix --apply` restores files from in-memory snapshots (never `git checkout --`). `--force` does not write files with uncommitted changes.
- `helmet()` insertion and secret → `process.env` are `safe: false` (dry-run suggestions; require `--unsafe` to apply).
- Typosquat: drop the collision allowlist; skip names that appear in a larger static top-packages list.
- Runtime README: signature-based stopgap, monitor recommended, sink-hooking in Phase 17. `bench` now also measures full Express request p50/p95.
- `publishConfig.provenance` removed; `npm publish --provenance` lives in the CI publish workflow only.

## 0.1.0 — 2026-10-13

First Core release (phases 1–10).

- Scanner: secrets, deps (OSV + typosquat), SAST taint-lite, config
- Reports: console, JSON, SARIF 2.1.0, Markdown, HTML
- Baseline (`--update-baseline`) and `fullshield-ignore RULE: reason`
- `fix` dry-run / `--apply` with git safety and test revert
- Runtime Express + Fastify guards (p95 inspect overhead < 1ms)
- `init` (GitHub/GitLab/pre-commit) and `notify` (Slack, webhook, SMTP)
