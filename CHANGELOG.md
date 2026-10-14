# Changelog

All notable changes to FullShield are documented here.

## Unreleased

### harden-5

- SSRF host normalization: IPv6 brackets, IPv4-mapped, decimal/octal/hex/short IPv4, trailing dots, resolve-at-connect, fetch redirect re-check.
- Attack corpus from PayloadsAllTheThings (vendored, attributed). Benign corpus ≥ 300. Per-category rates printed in verify.
- `RASP-SINKS.md` inventory. Async ALS tests (fs/promises, exec/spawn, sqlite, fetch, http). pg/mysql2 mocked query hooks.

### Frontier (experimental)

- **Phase 21:** MCP server (`FULLSHIELD_EXPERIMENTAL_MCP=1`, read-only; `propose_fix` returns diffs only) and LLM-app rules `LLM-001`–`LLM-005` (`FULLSHIELD_EXPERIMENTAL_LLM=1`).
- **Phase 20:** exploit confirm (`FULLSHIELD_EXPERIMENTAL_CONFIRM=1`). Scope lock: localhost / 127.0.0.1 / FullShield-started container only (refuses public DNS names and IPv6). Harmless canaries for SQLi / CMDi / path / IDOR.
- **Phase 19:** supply-chain defense + `fullshield install` (`FULLSHIELD_EXPERIMENTAL_SUPPLY=1`). Static only (never executes packages). Seeded install-script + `.npmrc`/network heuristic, version-diff behavior change, cooldown, lockfile host, dependency confusion, provenance drop. Registry locked to `registry.npmjs.org`.
- **Phase 18:** virtual patches (`scan --emit-virtual-patches`, `FULLSHIELD_EXPERIMENTAL_VPATCH=1`), egress allowlist, `honey init` (`FULLSHIELD_EXPERIMENTAL_HONEY=1`), threat score log→challenge→block.
- **Phase 17 RASP:** structure-change sink hooks (`node:sqlite`, `child_process`, `fs`, `http(s)`/`fetch`, plus load-time wraps for `pg`/`mysql2`/…). Off unless `FULLSHIELD_EXPERIMENTAL_RASP=1`. Default `monitor`. Fail-open on hook errors. Activate with `--import fullshield/runtime/register` or `import 'fullshield/runtime/auto'`.

## 0.1.0 — 2026-10-14

First public alpha (Core 1–10, Pro 11–16, harden-1–4).

**Shipped:** scan (deps + reachability, secrets, SAST, config), reports, baseline, fix, runtime guard, watch, edge, SBOM, CI gate.

**Experimental AI (0.1.0):** `scan --ai explain` and `fix --ai` only. Explain never shows a verdict. `--ai triage` and `--ai logic` are not a CLI surface.

**Publishing:** npm trusted publishing (OIDC) + `--provenance`. No `NPM_TOKEN`.

### harden-4

- Live Ollama path behind `FULLSHIELD_AI_LIVE=1`; `npm run test:live-ai` is never CI. Honest results in `benchmarks/AI-REPORT.md`.
- Yarn/pnpm lockfile edges; `reachability-unknown` keeps severity when edges are missing.
- LRU caps on the rate-limiter IP map and anomaly route/param maps.
- Mutation-smoke covers EDGE-*, AI-INJECT-001, DEPS-NOLOCK-001, and interproc taint.
- README: `--ai` experimental; AI-INJECT-001 is a three-phrase heuristic.

### Pro (11–16)

- `watch` alerts only on new OSV hits.
- `edge` GET/HEAD posture (CDN/WAF headers, HTTPS, security headers, exposure probes).
- AI provider layer (off by default). `AI-INJECT-001` phrase heuristic.
- Runtime anomaly baselines (no LLM).

### Core (1–10) and harden-1–3

- Secrets, deps (OSV + typosquat), SAST taint (intra + interproc depth 5), config.
- Reachability: reachable / imported-not-called (−1) / reachable-via-dependency (kept) / not-imported (−2). Dev-only overlay.
- Reports: console, JSON, SARIF 2.1.0, Markdown, HTML.
- `fix --apply` snapshot restore; helmet/secret-env are `safe: false`.
- Runtime Express + Fastify guards. `init` and `notify`.
