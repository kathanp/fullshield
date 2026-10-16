# Changelog

All notable changes to FullShield are documented here.

## Unreleased

### Phase 32 — experimental response DLP

- Optional `shieldGuard({ dlp: { mode: 'monitor' | 'mask' | 'block' } })` inspects outgoing JSON/text (size-capped at 64 KB) for secret patterns (same regexes as the secrets module), stack traces, internal IPs/hostnames, Luhn card numbers, and bulk emails on a one-email route.
- Behind `FULLSHIELD_EXPERIMENTAL_DLP=1`. Without the flag, `shieldGuard` and default `scan` are unchanged. `mask` replaces matches; `block` returns 500 `{ error: 'internal error' }`. Events go to `onEvent`. Over-cap bodies are skipped and counted.

### Phase 31 — supply chain, advanced + VEX

- Experimental (`FULLSHIELD_EXPERIMENTAL_VEX=1` / `scan --experimental-vex`): self-replicating worm indicators (`SUPPLY-WORM-001`) and workflow/git-hook/CI writes (`SUPPLY-WORKFLOW-001`). Default `scan` is unchanged.
- Transitive `FixProposal.kind = 'dependency-override'` (unsafe) when the parent has no fixed release. Writes npm `overrides` / pnpm `pnpm.overrides` / yarn `resolutions` into `package.json` and prints `run npm install`. The lockfile is not edited.
- Provenance coverage score (% of deps with provenance; unknown is not counted as present) with history-DB trend helpers.
- `fullshield vex --format openvex|cyclonedx` from reachability. `not_affected` + `vulnerable_code_not_in_execute_path` only when reachability is `not-imported`; otherwise `under_investigation`. Never guessed.

### Phase 30 — secrets, advanced (experimental)

- `scan --history` streams `git log -p`, dedupes by blob hash, and reports first-introduced commit + still-at-HEAD. Respects baseline and suppressions.
- `scan --bundle <dir>` scans `dist/`, `.next/static`, and `build/` for browser-exposed keys, including `NEXT_PUBLIC_*` / `VITE_*` secret-shaped values (`SECRET-BUNDLE-001`).
- `--verify-secrets` is opt-in, never default, never in generated CI templates. Requires `--i-own-these-credentials`. Read-only identity endpoints only (AWS STS GetCallerIdentity, GitHub `GET /user`, Stripe `GET /v1/balance`, Slack `auth.test`). Results: `live` \| `revoked` \| `unknown`. Never logs the key.
- Behind `FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1` / `scan --experimental-secrets-adv`. CLI flags do nothing useful without that flag. Default `scan` does not emit Phase-30-only rule IDs.

### Phase 29 — new vulnerability classes

- Experimental extra SAST/config classes (`FULLSHIELD_EXPERIMENTAL_CLASSES=1` / `scan --experimental-classes`): ReDoS, insecure deserialization, XXE, unrestricted upload, cookie flags, CSRF, mass assignment, timing-safe compare, password-hash cost, GraphQL introspection/depth, and `trust proxy` + IP rate limits. Default `scan` is unchanged.

- Publish CI uses `npm publish --provenance --access public` (no staged-manifest edits). The unpublished `v0.1.2` tag was deleted.
- CI: push to `next` runs `verify` on ubuntu-24.04 × Node 24 only. The full 6-job matrix (and the non-blocking `bench` job) runs on pull requests to `main` and on push to `main`. Required checks on `main` stay the six matrix jobs.

### Phase 28 — framework coverage

- Experimental Next.js / NestJS / Hono / Koa taint sources and AUTH (`FULLSHIELD_EXPERIMENTAL_FRAMEWORKS=1` / `scan --experimental-frameworks`). Default `scan` is unchanged.
- Runtime adapters `fullshield/runtime/koa` and `fullshield/runtime/hono` (optional peers; not required dependencies).

### NoSQL constructed-filter values

**New stable findings — may change CI results; use `--update-baseline`:**

- `SAST-NOSQLI-001` — request input used as a Mongo filter value (e.g. `{ password: req.body.password }`) at medium confidence, unless the value is coerced (`String()` / `Number()` / `Boolean()`), schema-validated (zod / joi / yup `.parse`), or `mongo-sanitize` / `express-mongo-sanitize` is applied. Fires only on MongoDB/mongoose receivers (file imports `mongodb`/`mongoose`, `collection.find` / `*Collection`, or a PascalCase model). Never Sequelize, Prisma, TypeORM, Knex, Drizzle, or unknown receivers.

`cr0hn/vulnerable-node` is now a seen holdout (no longer untouched).

### Phase 26c — engine gaps from the goof holdout

- Taint: method-call return inherits receiver taint; same-file helper parameters are seeded from tainted arguments; imported functions that return taint taint their call sites.
- Path: `extractAllTo` / `extractAll` / `extract` on a tainted archive object (zip-slip receiver).
- Config: missing helmet is attributed to the `express()` line when no commented-out helmet is present.
- Deps: OSV hits on direct dependencies are attributed to the `package.json` name line when a hit exists (still no invented advisories under `--offline-safe`).
- Multipart uploads: `req.files` is a taint source.
- `nodejs-goof` is a seen holdout. `cr0hn/vulnerable-node` is an untouched holdout scanned once. Precision in `BENCHMARK.md` is labeled self-triaged, unverified.

### Phase 26b — stable public-bench misses

**New stable findings — may change CI results; use `--update-baseline`:**

- `SAST-NOSQLI-001` — Mongo `$where` with a tainted string
- `SAST-REDIRECT-001` — destructured `{ query }` as a taint source (`res.redirect(query.to)`)
- `SAST-CRYPTO-001` — `md5(tainted)` used as a reset token
- `SAST-XSS-001` — `autoescape: false`
- `CONFIG-HELMET-001` — commented-out `helmet` (line-attributed; not a new detection on NodeGoat)
- `CONFIG-DIRLIST-001` — `serveIndex()` directory listing
- `SECRET-SESSION-001` — hardcoded `express-session` secret

Remaining in-scope misses (Swig `{{ }}` template line, JSON XSS, `includes()` allowlist, nested `{ _id: req.body.id }`, deps lockfile/offline, DVNA calc vs eval) stay in README Known limitations. Ground truth files were not edited to improve numbers.

Holdout: `bench:public` also clones pinned `snyk-labs/nodejs-goof`. Rules are not tuned from that app.

### Phase 27 — SAST + RASP coverage gaps

- RASP treats extra tokens in unquoted numeric SQL (`WHERE id = 1 OR 1=1`) as a structure change; a single number (`42`) stays allowed.
- Experimental SAST sinks (`FULLSHIELD_EXPERIMENTAL_SAST_GAPS=1` / `scan --experimental-sast-gaps`): Prisma `$queryRawUnsafe` / `$executeRawUnsafe` / `Prisma.raw`, Knex `raw`/`whereRaw`/`orderByRaw`, TypeORM `createQueryBuilder().where(concat)`, Drizzle `sql.raw`, mongoose `$where`, `spawn('sh', ['-c'])`, execa `shell: true`, zx `$.raw` / `{ quote: false }`. Prisma `$queryRaw` tagged templates and default zx `$` are not flagged. Default `scan` is unchanged.
- RASP load-time hooks for `@prisma/client`, `sequelize`, `knex`, `typeorm`, `drizzle-orm`, and mongoose `$where`.
- Attack corpus adds ≥10 cases each for `numeric-sql`, `orm-raw`, and `template-shell`. Benign corpus still 0 blocked.

### Phase 26 — public benchmark harness

- `npm run bench:public` clones pinned OWASP NodeGoat, Juice Shop, and DVNA SHAs, scans with `--json --offline-safe`, and writes `BENCHMARK.md`. Ground truth is exhaustive vs each app’s official docs, with `inScope` and `"reviewed": false`. Unmatched findings are triaged in `bench/<app>/triage.json`.
- CI job `bench` (ubuntu-24.04, Node 24) uploads `BENCHMARK.md` and is non-blocking.
- `scan --offline-safe` is an alias of `--offline`.

## 0.1.1 — 2026-10-15

### Phase 25 — 0.1.1 hardening (Windows + lazy SQLite)

- CI matrix is Linux, macOS, and Windows × Node 22 and 24.
- `node:sqlite` is loaded only when history/confirm open a database. `node --import fullshield/runtime/register -e "1"` prints nothing on stderr. Runtime entry points do not statically import sqlite.
- Dashboard `HistoryDb.close()` is idempotent and uses try/finally so Windows can unlink `history.db`.
- Fixer/agent diffs are `core.autocrlf`-independent: normalize to `\n` for compare, restore the file's original EOL on apply. Git pathspecs use POSIX slashes.
- `--import` child processes use `pathToFileURL(...).href` (`importHref`), never a bare absolute path.
- Flood test measures retained-heap delta after GC (< 10 MB) and asserts LRU sizes (512 / 64 / 128). Rate limiter covers the exact window edge and empty-then-refill.
- CI pins `ubuntu-24.04` and uses checkout/setup-node/upload-artifact v7 (Node 24 runtime).
- `@modelcontextprotocol/sdk` and `zod` are optional peerDependencies, lazy-imported only by `fullshield mcp`. Other scan/runtime deps stay required.
- `npm pack` ships `README.md` at the tarball root. `package.json` has no empty `readme` field (that left the npm packument as `"readme": ""`).

## 0.1.0 — 2026-10-14

First public alpha (Core 1–10, Pro 11–16, Frontier 17–24 behind flags, harden-1–6).

**Shipped (stable):** scan (deps + reachability, secrets, SAST, config), reports, baseline, fix, runtime guard, watch, edge, SBOM, CI gate.

**Experimental flags (off by default):**
- `scan --ai explain` and `fix --ai` only. Explain never shows a verdict. `--ai triage` and `--ai logic` are not a CLI surface. Live Ollama is `FULLSHIELD_AI_LIVE=1` (never CI).
- `FULLSHIELD_EXPERIMENTAL_RASP=1` — structure-change sink hooks (`--import fullshield/runtime/register` or `import 'fullshield/runtime/auto'`).
- `FULLSHIELD_EXPERIMENTAL_VPATCH=1` — `scan --emit-virtual-patches`.
- `FULLSHIELD_EXPERIMENTAL_HONEY=1` — `honey init`.
- `FULLSHIELD_EXPERIMENTAL_SUPPLY=1` — `fullshield install` (static only).
- `FULLSHIELD_EXPERIMENTAL_CONFIRM=1` — localhost / 127.0.0.1 / FullShield-started container only.
- `FULLSHIELD_EXPERIMENTAL_MCP=1` — read-only MCP (`propose_fix` returns diffs only).
- `FULLSHIELD_EXPERIMENTAL_LLM=1` — `LLM-001`–`LLM-005`.
- `FULLSHIELD_EXPERIMENTAL_PLATFORM=1` — threat-model, `--changed`/`--since`, workspaces, local dashboard.
- `FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1` — `report --compliance` (not a certification or audit).
- `FULLSHIELD_EXPERIMENTAL_IAC=1` — light IaC rules.
- `FULLSHIELD_EXPERIMENTAL_AGENT=1` — remediation agent (localhost mock API + local git only).

**Publishing:** npm trusted publishing (OIDC) stages with `--provenance`; a maintainer approves with 2FA. No `NPM_TOKEN`.

### harden-5

- SSRF host normalization: IPv6 brackets, IPv4-mapped, decimal/octal/hex/short IPv4, trailing dots, resolve-at-connect, fetch redirect re-check.
- Attack corpus from PayloadsAllTheThings (vendored, attributed). Benign corpus ≥ 300. Per-category rates printed in verify.
- `RASP-SINKS.md` inventory. Async ALS tests (fs/promises, exec/spawn, sqlite, fetch, http). pg/mysql2 mocked query hooks.

### harden-6

- `DEPS-MALICIOUS-001` for OSV `MAL-` / malicious classification: always critical, never downgraded by reachability or dev-only.
- Honeytokens: decoy-route hits are low + aggregated; only canary credential use is critical. Threat auto-block is opt-in with a max duration (shared-IP / NAT risk). `honey init` writes fake values that secrets do not flag and appends them to `.gitignore`.
- Official MCP SDK stdio (`fullshield mcp --stdio`) plus SDK-client tests.

### Frontier (experimental)

- **Phase 24:** remediation agent (`FULLSHIELD_EXPERIMENTAL_AGENT=1`). Opens PRs via a localhost mock API against a local bare repo only. Never merges, never pushes to protected branches, stops on test failure.
- **Phase 23:** compliance mapping (OWASP/CWE/ASVS/PCI; every report says not a certification or audit) and light IaC (`FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1` / `FULLSHIELD_EXPERIMENTAL_IAC=1`).
- **Phase 22:** threat-model, incremental `--changed`/`--since`, workspaces, local dashboard (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). Dashboard binds 127.0.0.1 and validates Host.
- **Phase 21:** MCP server (`FULLSHIELD_EXPERIMENTAL_MCP=1`, read-only; `propose_fix` returns diffs only) and LLM-app rules `LLM-001`–`LLM-005` (`FULLSHIELD_EXPERIMENTAL_LLM=1`).
- **Phase 20:** exploit confirm (`FULLSHIELD_EXPERIMENTAL_CONFIRM=1`). Scope lock: localhost / 127.0.0.1 / FullShield-started container only (refuses public DNS names and IPv6). Harmless canaries for SQLi / CMDi / path / IDOR.
- **Phase 19:** supply-chain defense + `fullshield install` (`FULLSHIELD_EXPERIMENTAL_SUPPLY=1`). Static only (never executes packages). Seeded install-script + `.npmrc`/network heuristic, version-diff behavior change, cooldown, lockfile host, dependency confusion, provenance drop. Registry locked to `registry.npmjs.org`.
- **Phase 18:** virtual patches (`scan --emit-virtual-patches`, `FULLSHIELD_EXPERIMENTAL_VPATCH=1`), egress allowlist, `honey init` (`FULLSHIELD_EXPERIMENTAL_HONEY=1`), threat score log→challenge→block.
- **Phase 17 RASP:** structure-change sink hooks (`node:sqlite`, `child_process`, `fs`, `http(s)`/`fetch`, plus load-time wraps for `pg`/`mysql2`/…). Off unless `FULLSHIELD_EXPERIMENTAL_RASP=1`. Default `monitor`. Fail-open on hook errors. Activate with `--import fullshield/runtime/register` or `import 'fullshield/runtime/auto'`.

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
