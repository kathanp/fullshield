# FullShield

**v0.1.1 / alpha.** One install for Node.js/TypeScript backends: detect → classify → report → notify → fix → gate (CI `--fail-on` + runtime monitor). It does not stop attacks by itself.

**Headline: dependency reachability.** A lockfile CVE is not the same as an unused package. FullShield classifies each OSV hit as `reachable` (imported and called), `imported-not-called` (−1), `reachable-via-dependency` (lockfile path from an imported direct dep — **severity kept**, path shown, e.g. `express > body-parser > qs`), `not-imported` (−2, only when no such path exists), or `reachability-unknown` (severity kept) when the lockfile format has no parsed dependency edges. DevDependency-only vulns are `info` with a `dev-only` note unless production sources import the package. Pair it with `fullshield sbom --format cyclonedx`.

```bash
npx fullshield scan
npx fullshield scan --json --fail-on high
npx fullshield scan --sarif fullshield.sarif
```

This is a `0.x` release. APIs may change. Do not treat it as a penetration test.

**Requires Node.js >= 22.13.** `node:sqlite` runs without `--experimental-sqlite` from 22.13.0 (the module is still experimental and is loaded only by history/confirm, not by `--import` register).

## Coverage map

| Layer | Covered by |
|---|---|
| Code vulnerabilities | `sast` (intra-function + cross-file taint, depth 5) |
| Dependencies (now + new CVEs later) | `deps` (OSV + **reachability**) + `watch` |
| Secrets | `secrets` + `scan --staged` / pre-commit hook |
| App/server config | `config` |
| Live app-layer signals | `runtime` (`fullshield/runtime/express` or `/fastify`) in **monitor** mode; **experimental** RASP sink hooks via `--import fullshield/runtime/register` (fail-open; not a prevention guarantee) |
| Edge/DDoS layer | `edge` checks that a CDN/WAF **exists** (headers only). Actual DDoS mitigation is the CDN. |
| AI assist (opt-in, **experimental**) | `scan --ai explain` and `fix --ai` only. Off by default: zero AI network calls. Explain never shows a verdict. Triage and logic hunter are not shipped. |
| LLM-app code (opt-in, **experimental**) | `LLM-001`–`LLM-005` (`FULLSHIELD_EXPERIMENTAL_LLM=1`). Phrase/AST heuristics, not a jailbreak defense. |
| Supply-chain install (opt-in, **experimental**) | `fullshield install` — static only; never executes packages. |
| Exploit confirm (opt-in, **experimental**) | `fullshield confirm` — localhost / 127.0.0.1 / FullShield-started container only. |
| Editor MCP (opt-in, **experimental**) | `fullshield mcp --stdio` — read-only; `propose_fix` returns diffs, never writes. |
| Threat model / dashboard (opt-in, **experimental**) | STRIDE+Mermaid sketch; dashboard binds 127.0.0.1 and locks `Host`. |
| Compliance / IaC (opt-in, **experimental**) | Mapping is **not a certification or audit**. IaC is ~10 high-value rules, not a full IaC scanner. |
| Remediation agent (opt-in, **experimental**) | Localhost mock GitHub API + local git only. Never merges, never pushes to `main`/`master`. |

## What it detects (Core)

- **SAST:** SQL/NoSQL injection, command injection, path traversal, `eval`/`new Function`/`vm`, SSRF, open redirects, JWT `decode`/`none`, weak crypto, prototype pollution, XSS (`res.send` HTML and `<%-` / `{{{` templates), missing auth middleware (low confidence). `AI-INJECT-001` is a **basic phrase heuristic** (three exact comment phrases: "ignore previous", "mark as safe", "AI reviewer") — not a prompt-injection defense.
- **Secrets:** AWS, Stripe, GitHub, Slack, Google, AI keys, PEM keys, DB URLs with passwords, hardcoded JWT secrets, committed `.env`.
- **Deps:** OSV vulnerabilities with reachability (`reachable` / `imported-not-called` / `reachable-via-dependency` / `not-imported` / `reachability-unknown`), `dev-only` info for unused devDependencies, lockfile deprecation notices, typosquat-suspicious *direct* dependency names. `DEPS-MALICIOUS-001` for OSV `MAL-` / malicious-classified advisories is **always critical** and is never downgraded (install scripts run at `npm install`). `DEPS-NOLOCK-001` when there is a manifest but no lockfile; exact `package.json` pins are still queried.
- **Config:** missing helmet, `express.json()` without a limit, CORS `*` + credentials, auth routes without a rate limiter, `err.stack` leaks, risky Dockerfiles, install scripts.

## Non-goals (honesty is a feature)

- Does **not** find business-logic or authorization bugs (IDOR, CSRF, missing ownership checks). It can flag routes with no auth middleware as *suspicious*, nothing more.
- Does **not** replace a penetration test.
- Does **not** auto-delete code. `fix --apply` writes patches on a clean git tree. If project tests fail, each written file is restored from a byte-for-byte snapshot taken before the write — never `git checkout --`. `--force` on a dirty tree still refuses to touch files that have uncommitted changes.
- v1 is **JS/TS only**. Other languages are out of scope.
- Cross-file taint follows `require`/`import` and method calls up to 5 hops and records a `trace` (also SARIF `codeFlows`). Nested closures and some dynamic dispatch are still missed.
- Runtime v1 is **signature-based** (payload regex + rate limit + body-size guard). It is a **stopgap monitor**, not a WAF. Prefer **`mode: 'monitor'`** in production until you have measured false-positive rate. Sink-hooking RASP is **experimental** (off by default; see below) and does not claim to prevent attacks.
- Only scan hosts and repos you own or are authorized to test.
- **Experimental features are off by default and are not product claims:**
  - RASP / virtual patches / honeytokens / threat auto-block: fail-open hooks; decoy-route hits are low and never auto-block; auto-block is opt-in (shared-IP / NAT risk).
  - `install` / supply-chain: static heuristics only; never a substitute for `npm audit` policy or a malware sandbox.
  - `confirm`: harmless canaries on localhost only; fail-open (`unconfirmed` is not a pass).
  - MCP / LLM-app rules: editor glue and shallow AST/phrase checks. Not a prompt-injection or tool-abuse guarantee.
  - Threat-model / incremental / dashboard: a route sketch and a local history UI. Not a STRIDE workshop or a hosted SOC.
  - `report --compliance` / `iac`: evidence-style mapping and a short IaC ruleset. **Not a certification or audit.**
  - `agent`: opens PRs against a **mock/localhost API and a local git remote**. It never talks to real GitHub, never merges, never pushes to protected branches.

## Known limitations

- Platforms: Linux, macOS, and Windows on Node 22.13+. Quoted filenames in dirty-tree tests are POSIX-only (Windows forbids `"` in names).
- `node:sqlite` is loaded only by history/confirm, not by `--import fullshield/runtime/register`. Dashboard closes every handle in `try/finally` (Windows cannot delete an open `history.db`).
- FullShield does not stop OS or SSH exploits (including regreSSHion). It scans Node/TS apps you own.

Experimental RASP structure-change scoring on the vendored PayloadsAllTheThings corpus (not a claim that live attacks are blocked):

- **SQL 42/42.** Quote-breakouts inside `'…'` (`' OR 1=1 --`, `'; DROP TABLE x; --`) are detected. Payloads `"-"`, `" "`, `"&"`, `"^"` were moved to the benign set: they stay inside one single-quoted string token and are not exploitable in that sink.
- **Shell 45/45.** Quote-breakouts that close a quoted `ls` argument (`'; id; '`, `"; id; "`) are detected. Payloads `";id;"`, `';id;'`, `"|id|"`, `'|id|'` were moved to the benign set: `;` / `|` stay inside one quoted word.

Path 51/51 and SSRF 39/39 on the same corpus. Benign corpus stays 0 blocked. Prefer `mode: 'monitor'`.

These fixtures are self-authored. Numeric SQL (`WHERE id = ` + input), ORM raw-query APIs (Prisma/Sequelize/Knex/TypeORM/Drizzle/`$where`), and template-literal shell (`exec(\`…${x}\`)`, `spawn('sh', ['-c', …])`, execa `shell: true`, zx `$.raw`) are covered in the attack corpus. Extra SAST sinks for those ORM / `sh -c` / execa / zx shapes stay behind `FULLSHIELD_EXPERIMENTAL_SAST_GAPS=1` (or `scan --experimental-sast-gaps`) so default `scan` behavior does not change. Mongo `$where` strings are **stable** SAST (Juice Shop track-order / reviews).

In-scope public-bench patterns we still do not claim (one line each):

- Swig `{{firstName}}` in `.html` — XSS only if autoescape is off in another file; we flag `autoescape: false`, not the template line.
- Juice Shop track-order XSS — server returns `res.json`; we do not treat JSON fields as HTML sinks.
- Juice Shop `url.includes(allowedUrl)` — weak allowlist helper is not a redirect sink; we flag `res.redirect(tainted)`.
- Juice Shop `{ _id: req.body.id }` — flagged as `SAST-NOSQLI-001` (medium) unless coerced (`String()`/`Number()`/`Boolean()`), schema-validated, or mongo-sanitize is applied. Same for goof `User.find({ password: req.body.password })`.
- `DEPS-VULN-001` — when an OSV hit exists, the finding is attributed to the `package.json` name line; `--offline-safe` on a cache-less clone still emits no OSV hits (`package.json:N` will not match).
- DVNA calculator “stack leak” — that line is `mathjs.eval` (`SAST-EVAL-001`), not `err.stack`.

Public-app in-scope detection on **unreviewed** ground truth (`"reviewed": false` in `bench/*/ground-truth.json`). These are not product recall claims. Matching is class + file + line ±3. Helmet comment-only line attribution is not counted.

- Seen holdout `snyk-labs/nodejs-goof` @ `add14ba59e98240d9e00a235dd7d42cd61ae9912`: 10/11 in-scope (unreviewed). Not a recall gain; this app was used to find engine gaps.
- Seen holdout `cr0hn/vulnerable-node` @ `d68f2a3c9277ece2c2feb9976052033bdecd7fbe`: 9/12 in-scope (unreviewed). Re-scored after the authorized NoSQL filter-value rule; not a recall gain.
- NodeGoat 5/7, Juice Shop 10/12, DVNA 9/10 (same unreviewed files; deps TPs need an OSV cache hit under `--offline-safe`).

Precision in [`BENCHMARK.md`](BENCHMARK.md) is self-triaged, unverified. Unsure counts on that run: NodeGoat 4, Juice Shop 46, DVNA 5, goof 4, vulnerable-node 29.

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

Runtime (does not load the scanner). **Signature-based stopgap — monitor mode recommended.**

```ts
import express from 'express';
import { shieldGuard } from 'fullshield/runtime/express';

const app = express();
app.use(shieldGuard({ mode: 'monitor', authRoutes: ['/login'] }));
```

**Experimental Frontier (off by default):** `FULLSHIELD_EXPERIMENTAL_VPATCH=1` + `scan --emit-virtual-patches`; `FULLSHIELD_EXPERIMENTAL_HONEY=1` + `fullshield honey init`.

**Experimental RASP** (Frontier, off by default): structure-change sink hooks via `node --import fullshield/runtime/register app.js` or `import 'fullshield/runtime/auto'` as the first import. Enable only with `FULLSHIELD_EXPERIMENTAL_RASP=1`. Default mode is `monitor` (events only). `FULLSHIELD_RASP_MODE=block` throws on structure-changing SQL/shell/path/NoSQL/SSRF/prototype input. Hooks **fail open**: a hook error logs `RASP-FAIL-OPEN-001` and the original call proceeds. Do not use block mode in production until you have measured the benign corpus on your app.

`npm run bench` reports `inspect()` p50/p95 (must stay under 1ms) and full Express request overhead p50/p95 with the middleware on the stack.

## Commands

| Command | Purpose |
|---|---|
| `scan` | Run deps, secrets, sast, config. `--json`, `--sarif`, `--markdown`, `--html`, `--fail-on`, `--offline`, `--staged`, `--update-baseline`. `--ai explain` is **experimental** (off by default; explanation text only, never a verdict) |
| `fix` | Dry-run patches (unsafe suggestions included). `--apply` writes only `safe: true` patches on a clean git tree. `--unsafe` is required for `helmet()` insertion and secret → `process.env` replacement. `--force` skips files with uncommitted changes. `--ai` is **experimental**: drafts a verified, reviewable diff for findings without a rule-based fix (never auto-merged). |
| `init` | Config + GitHub/GitLab CI + pre-commit hook |
| `notify` | Slack / generic webhook / SMTP summary of the last scan |
| `sbom` | CycloneDX 1.5 JSON (`--format cyclonedx`, `--out file`) |
| `watch` | Rescan dependencies; alert (webhook / exit 1) only on **new** OSV hits vs last scan. `init` writes a daily GitHub Action. |
| `edge` | GET/HEAD posture check on a URL you pass: CDN/WAF, HTTPS redirect, security headers, `/.env` / `/.git` exposure. No crawl, no payloads. |
| `install` | **Experimental** install-guard (`FULLSHIELD_EXPERIMENTAL_SUPPLY=1`). Static analysis only; never runs package scripts. Registry reads are `registry.npmjs.org` only. |
| `confirm` | **Experimental** exploit confirm (`FULLSHIELD_EXPERIMENTAL_CONFIRM=1`). localhost / 127.0.0.1 / FullShield-started container only. Harmless canaries only. |
| `mcp` | **Experimental** MCP server (`FULLSHIELD_EXPERIMENTAL_MCP=1`). Official SDK stdio: `fullshield mcp --stdio`. Requires optional peers `@modelcontextprotocol/sdk` and `zod` (`npm i -D @modelcontextprotocol/sdk zod`); missing peers print an install hint, not a stack dump. Read-only tools: `scan`, `get_findings`, `explain_finding`, `propose_fix` (diff only, never writes), `verify_fix` (temp copy). |
| `honey init` | **Experimental** honeytokens (`FULLSHIELD_EXPERIMENTAL_HONEY=1`). Decoy routes are **low** severity and aggregated per IP; only use of a canary **credential** is critical. Auto-block is off unless `threatAutoBlock` is set (shared-IP / NAT risk; max duration applies). Decoys are fake values added to `.gitignore`. |
| `threat-model` | **Experimental** STRIDE + Mermaid (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). |
| `report --serve` | **Experimental** local dashboard (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). Binds **127.0.0.1 only** and rejects any `Host` other than localhost/127.0.0.1 (DNS rebinding). No state-changing GET. |
| `report --compliance pci` | **Experimental** evidence-style mapping (`FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1`). **Not a certification or audit.** |
| `iac` | **Experimental** light IaC (`FULLSHIELD_EXPERIMENTAL_IAC=1`): GHA, Terraform, Kubernetes, docker-compose. Not a full IaC scanner. |
| `agent` | **Experimental** remediation agent (`FULLSHIELD_EXPERIMENTAL_AGENT=1`). Mock/localhost GitHub API + local git remote only — never a real network. Never merges, never pushes to `main`/`master`. `--max-prs` (default 3). |
| `scan --changed` / `--since` | **Experimental** incremental scan (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). |
| `scan --experimental-sast-gaps` | **Experimental** extra SAST sinks: ORM raw SQL, mongoose `$where`, `spawn('sh', ['-c'])`, execa `shell: true`, zx `$.raw` (`FULLSHIELD_EXPERIMENTAL_SAST_GAPS=1`). |

Inline ignore (reason required): `// fullshield-ignore SAST-SQLI-001: reviewed`

## Rule docs

See [`rules/README.md`](rules/README.md).

## Benchmarks

Public-app detection results (OWASP NodeGoat, Juice Shop, DVNA, seen holdouts `snyk-labs/nodejs-goof` and `cr0hn/vulnerable-node`) live in [`BENCHMARK.md`](BENCHMARK.md). Those ground-truth files are still `"reviewed": false`. Holdout numbers are listed under Known limitations and are on unreviewed ground truth. Precision in `BENCHMARK.md` is self-triaged, unverified. Self-authored fixture notes live in [`benchmarks/REPORT.md`](benchmarks/REPORT.md). Live Ollama smoke results (not CI) live in [`benchmarks/AI-REPORT.md`](benchmarks/AI-REPORT.md).

### Cursor MCP (`mcp.json`)

```json
{
  "mcpServers": {
    "fullshield": {
      "command": "npx",
      "args": ["fullshield", "mcp", "--stdio"],
      "env": { "FULLSHIELD_EXPERIMENTAL_MCP": "1" }
    }
  }
}
```

`propose_fix` returns a diff only. It never writes your tree.

See [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), and [`RELEASING.md`](RELEASING.md).

## License

MIT
