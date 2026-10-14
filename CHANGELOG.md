# Changelog

All notable changes to FullShield are documented here.

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
