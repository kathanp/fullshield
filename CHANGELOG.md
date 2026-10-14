# Changelog

All notable changes to FullShield are documented here.

## Unreleased — phase-16

- `scan --ai logic`: recorded-fixture IDOR / mass-assignment hunter. Findings are `source: ai`, confidence medium, and never fail CI.
- Runtime `shieldGuard({ anomaly: { learnMinutes } })`: per-route baseline, 401 spikes, new params, 404 bursts (no LLM).

## Unreleased — phase-15

- `scan --ai triage` / `--ai explain`: labels and explanations from recorded fixtures. Never removes high/critical findings.
- `fix --ai`: verify loop in a temp copy (rescan + tests, max 2 attempts). Reviewable diff only; never writes the user tree.

## Unreleased — phase-14

- AI provider layer (Anthropic / OpenAI / Ollama), off by default. Secrets redacted from outbound payloads. Cost cap + response cache. `AI-INJECT-001` for comments that try to manipulate AI reviewers.

## Unreleased — phase-12

- `fullshield edge <url>`: CDN/WAF, HTTPS redirect, security headers, exposure probes (GET/HEAD only).

## Unreleased — phase-11

- `fullshield watch` rescans dependencies and alerts only on new OSV findings vs last scan.
- `init` writes `.github/workflows/fullshield-watch.yml` (daily cron).

## Unreleased — harden-3

- Transitive OSV hits on a lockfile path from an imported direct dependency are `reachable-via-dependency` (severity kept; path recorded). `not-imported` (−2) only when no such path exists.
- DevDependency-only vulns are downgraded to info with a `dev-only` note unless production sources import the package.
- Sanitizers are sink-specific: `JSON.parse` / generic `parse` never clear taint; `encodeURIComponent` is URL/redirect only; HTML escape is XSS only; zod/joi/yup clear taint only for the validated result.

## Unreleased — phase-13

- Cross-file taint (call graph, depth 5) records `Finding.trace` and SARIF `codeFlows`.
- Dependency reachability: `reachable` / `imported-not-called` (−1) / `not-imported` (−2).
- `fullshield sbom --format cyclonedx` emits CycloneDX 1.5 JSON with vuln references.

## Unreleased — harden-2

- `DEPS-NOLOCK-001` (info) when `package.json` exists without a lockfile; exact pins are still queried on OSV.
- `topPackages.ts` documents its source/date; NodeGoat/DVNA-only names removed.
- In-process CLI tests raise `src/cli/program.ts` coverage; SARIF validator branch coverage ≥ 75%.

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
