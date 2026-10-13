# FullShield

**v0.1.0 / alpha.** One install for Node.js/TypeScript backends: detect → classify → report → notify → fix → prevent (CI gate + runtime guard).

```bash
npx fullshield scan
npx fullshield scan --json --fail-on high
npx fullshield scan --sarif fullshield.sarif
```

This is a `0.x` release. APIs may change. Do not treat it as a penetration test.

## Coverage map

| Layer | Covered by |
|---|---|
| Code vulnerabilities | `sast` (intra-function taint) |
| Dependencies (now + new CVEs later) | `deps` (OSV) |
| Secrets | `secrets` + `scan --staged` / pre-commit hook |
| App/server config | `config` |
| Live app-layer attacks | `runtime` (`fullshield/runtime/express` or `/fastify`) |
| Edge/DDoS layer | **not in Core** — use a CDN/WAF |

## What it detects (Core)

- **SAST:** SQL/NoSQL injection, command injection, path traversal, `eval`/`new Function`/`vm`, SSRF, open redirects, JWT `decode`/`none`, weak crypto, prototype pollution, XSS (`res.send` HTML and `<%-` / `{{{` templates), missing auth middleware (low confidence).
- **Secrets:** AWS, Stripe, GitHub, Slack, Google, AI keys, PEM keys, DB URLs with passwords, hardcoded JWT secrets, committed `.env`.
- **Deps:** OSV vulnerabilities, lockfile deprecation notices, typosquat-suspicious *direct* dependency names.
- **Config:** missing helmet, `express.json()` without a limit, CORS `*` + credentials, auth routes without a rate limiter, `err.stack` leaks, risky Dockerfiles, install scripts.

## Non-goals (honesty is a feature)

- Does **not** find business-logic or authorization bugs (IDOR, CSRF, missing ownership checks). It can flag routes with no auth middleware as *suspicious*, nothing more.
- Does **not** replace a penetration test.
- Does **not** auto-delete code. `fix --apply` writes patches on a clean git tree and reverts if tests fail.
- v1 is **JS/TS only**. Other languages are out of scope.
- Taint is **intra-function**. Cross-file flows (route → DAO) are a known miss until Pro (Phase 13).
- Runtime v1 uses payload signatures + rate limits. Full RASP sink-hooking is Frontier, not Core.
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

Runtime (does not load the scanner):

```ts
import express from 'express';
import { shieldGuard } from 'fullshield/runtime/express';

const app = express();
app.use(shieldGuard({ mode: 'block', authRoutes: ['/login'] }));
```

## Commands

| Command | Purpose |
|---|---|
| `scan` | Run deps, secrets, sast, config. `--json`, `--sarif`, `--markdown`, `--html`, `--fail-on`, `--offline`, `--staged`, `--update-baseline` |
| `fix` | Dry-run patches. `--apply` on a clean git tree; `--force` / `--unsafe` / `--no-branch` |
| `init` | Config + GitHub/GitLab CI + pre-commit hook |
| `notify` | Slack / generic webhook / SMTP summary of the last scan |

Inline ignore (reason required): `// fullshield-ignore SAST-SQLI-001: reviewed`

## Rule docs

See [`rules/README.md`](rules/README.md).

## Benchmarks

Honest NodeGoat / DVNA results (what we found and what we missed) live in [`benchmarks/REPORT.md`](benchmarks/REPORT.md).

## License

MIT
