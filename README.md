# FullShield

**v0.1.0 / alpha.** One install for Node.js/TypeScript backends: detect → classify → report → notify → fix → prevent (CI gate + runtime guard).

**Headline: dependency reachability.** A lockfile CVE is not the same as an unused package. FullShield classifies each OSV hit as `reachable` (imported and called), `imported-not-called` (−1), `reachable-via-dependency` (lockfile path from an imported direct dep — **severity kept**, path shown, e.g. `express > body-parser > qs`), `not-imported` (−2, only when no such path exists), or `reachability-unknown` (severity kept) when the lockfile format has no parsed dependency edges. DevDependency-only vulns are `info` with a `dev-only` note unless production sources import the package. Pair it with `fullshield sbom --format cyclonedx`.

```bash
npx fullshield scan
npx fullshield scan --json --fail-on high
npx fullshield scan --sarif fullshield.sarif
```

This is a `0.x` release. APIs may change. Do not treat it as a penetration test.

## Coverage map

| Layer | Covered by |
|---|---|
| Code vulnerabilities | `sast` (intra-function + cross-file taint, depth 5) |
| Dependencies (now + new CVEs later) | `deps` (OSV + **reachability**) + `watch` |
| Secrets | `secrets` + `scan --staged` / pre-commit hook |
| App/server config | `config` |
| Live app-layer attacks | `runtime` (`fullshield/runtime/express` or `/fastify`) |
| Edge/DDoS layer | `edge` checks that a CDN/WAF **exists** (headers only). Actual DDoS mitigation is the CDN. |
| AI assist (opt-in, **experimental**) | `--ai triage\|explain\|logic` and `fix --ai`. Off by default: zero AI network calls. Recorded fixtures in CI. Live path is `npm run test:live-ai` (local Ollama; never CI). AI findings never fail CI. |

## What it detects (Core)

- **SAST:** SQL/NoSQL injection, command injection, path traversal, `eval`/`new Function`/`vm`, SSRF, open redirects, JWT `decode`/`none`, weak crypto, prototype pollution, XSS (`res.send` HTML and `<%-` / `{{{` templates), missing auth middleware (low confidence). `AI-INJECT-001` is a **basic phrase heuristic** (three exact comment phrases: "ignore previous", "mark as safe", "AI reviewer") — not a prompt-injection defense.
- **Secrets:** AWS, Stripe, GitHub, Slack, Google, AI keys, PEM keys, DB URLs with passwords, hardcoded JWT secrets, committed `.env`.
- **Deps:** OSV vulnerabilities with reachability (`reachable` / `imported-not-called` / `reachable-via-dependency` / `not-imported` / `reachability-unknown`), `dev-only` info for unused devDependencies, lockfile deprecation notices, typosquat-suspicious *direct* dependency names. `DEPS-NOLOCK-001` when there is a manifest but no lockfile; exact `package.json` pins are still queried.
- **Config:** missing helmet, `express.json()` without a limit, CORS `*` + credentials, auth routes without a rate limiter, `err.stack` leaks, risky Dockerfiles, install scripts.

## Non-goals (honesty is a feature)

- Does **not** find business-logic or authorization bugs (IDOR, CSRF, missing ownership checks). It can flag routes with no auth middleware as *suspicious*, nothing more.
- Does **not** replace a penetration test.
- Does **not** auto-delete code. `fix --apply` writes patches on a clean git tree. If project tests fail, each written file is restored from a byte-for-byte snapshot taken before the write — never `git checkout --`. `--force` on a dirty tree still refuses to touch files that have uncommitted changes.
- v1 is **JS/TS only**. Other languages are out of scope.
- Cross-file taint follows `require`/`import` and method calls up to 5 hops and records a `trace` (also SARIF `codeFlows`). Nested closures and some dynamic dispatch are still missed.
- Runtime v1 is **signature-based** (payload regex + rate limit + body-size guard). It is a **stopgap**. Prefer **`mode: 'monitor'`** in production until you have measured false-positive rate. Sink-hooking RASP is Phase 17 (Frontier), not Core.
- Only scan hosts and repos you own or are authorized to test.

## Quick start

```bash
npm i -D fullshield
npx fullshield init
npx fullshield scan --fail-on high
```

Library:

```ts
import { scan } from 'fullshield';
const result = await scan({ cwd: process.cwd() });
```

Runtime (does not load the scanner). **Signature-based stopgap — monitor mode recommended.** Sink-hooking arrives in Phase 17.

```ts
import express from 'express';
import { shieldGuard } from 'fullshield/runtime/express';

const app = express();
app.use(shieldGuard({ mode: 'monitor', authRoutes: ['/login'] }));
```

`npm run bench` reports `inspect()` p50/p95 (must stay under 1ms) and full Express request overhead p50/p95 with the middleware on the stack.

## Commands

| Command | Purpose |
|---|---|
| `scan` | Run deps, secrets, sast, config. `--json`, `--sarif`, `--markdown`, `--html`, `--fail-on`, `--offline`, `--staged`, `--update-baseline`. `--ai triage\|explain\|logic` is **experimental** (off by default; zero AI network calls unless you opt in) |
| `fix` | Dry-run patches (unsafe suggestions included). `--apply` writes only `safe: true` patches on a clean git tree. `--unsafe` is required for `helmet()` insertion and secret → `process.env` replacement. `--force` skips files with uncommitted changes. `--ai` is **experimental**: drafts a verified, reviewable diff for findings without a rule-based fix (never auto-merged). |
| `init` | Config + GitHub/GitLab CI + pre-commit hook |
| `notify` | Slack / generic webhook / SMTP summary of the last scan |
| `sbom` | CycloneDX 1.5 JSON (`--format cyclonedx`, `--out file`) |
| `watch` | Rescan dependencies; alert (webhook / exit 1) only on **new** OSV hits vs last scan. `init` writes a daily GitHub Action. |
| `edge` | GET/HEAD posture check on a URL you pass: CDN/WAF, HTTPS redirect, security headers, `/.env` / `/.git` exposure. No crawl, no payloads. |

Inline ignore (reason required): `// fullshield-ignore SAST-SQLI-001: reviewed`

## Rule docs

See [`rules/README.md`](rules/README.md).

## Benchmarks

Honest NodeGoat / DVNA results (what we found and what we missed) live in [`benchmarks/REPORT.md`](benchmarks/REPORT.md). Live Ollama smoke results (not CI) live in [`benchmarks/AI-REPORT.md`](benchmarks/AI-REPORT.md).

## License

MIT
