# Changelog

All notable changes to FullShield are documented here.

## 0.1.0 — 2026-10-13

First Core release (phases 1–10).

- Scanner: secrets, deps (OSV + typosquat), SAST taint-lite, config
- Reports: console, JSON, SARIF 2.1.0, Markdown, HTML
- Baseline (`--update-baseline`) and `fullshield-ignore RULE: reason`
- `fix` dry-run / `--apply` with git safety and test revert
- Runtime Express + Fastify guards (p95 inspect overhead < 1ms)
- `init` (GitHub/GitLab/pre-commit) and `notify` (Slack, webhook, SMTP)
