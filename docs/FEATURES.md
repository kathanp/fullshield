# FullShield features (1.3.1)

Inventory of what this tree ships. Default use is a Node.js/TypeScript scan that detects, classifies, reports, notifies, suggests fixes, and can gate CI. Experimental features stay off unless their flag is set to `1`.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## Stable (on by default)

### Scan modules

`fullshield scan` runs all four:

- **Dependencies** — OSV advisories with reachability (`reachable`, `imported-not-called`, `reachable-via-dependency`, `not-imported`, `reachability-unknown`), dev-only notes, lockfile deprecation, typosquat names, malicious `MAL-` advisories (always critical), missing lockfile.
- **Secrets** — AWS, Stripe, GitHub, Slack, Google, AI keys, PEM keys, DB URLs with passwords, hardcoded JWT secrets, committed `.env`.
- **SAST** — SQL/NoSQL injection, command injection, path traversal, `eval` / `new Function` / `vm`, SSRF, open redirects, JWT `decode` / `none`, weak crypto, prototype pollution, XSS, missing auth middleware (low confidence), plus a basic comment-phrase check (`AI-INJECT-001`).
- **Config** — missing helmet, unbounded `express.json()`, CORS `*` with credentials, auth routes without a rate limiter, `err.stack` leaks, risky Dockerfiles, install scripts.

### Commands and outputs

- `scan` with `--json`, `--sarif`, `--markdown`, `--html`, `--fail-on`, `--offline`, `--staged`, `--update-baseline`
- `fix` (dry-run patches; `--apply` writes only on a clean git tree)
- `init` (config, GitHub/GitLab CI, pre-commit hook)
- `notify` (Slack, webhook, or SMTP)
- `sbom --format cyclonedx`
- `watch` (alert only on a new OSV hit)
- `edge` (CDN/WAF, HTTPS, security headers, `/.env` / `/.git` on a URL you pass)
- `doctor`
- Library API: `import { scan } from 'fullshield'`
- Runtime monitor: `fullshield/runtime/express` and `/fastify` (`shieldGuard`, signature-based, monitor mode)
- Inline ignore: `// fullshield-ignore RULE-ID: reason`

## Experimental (off until the flag is `1`)

- **AI** — `scan --ai explain`, `fix --ai` (explanation or a reviewable diff; no verdict, no auto-merge)
- **LLM-app rules** — `LLM-001`–`LLM-005`
- **Supply chain** — `install` (static only), provenance, VEX, capability profiles, `deps-diff`, `npm-audit-diff`, deeper npm checks
- **Exploit confirm** — localhost canaries only
- **Editor MCP** — read-only; `propose_fix` returns a diff and does not write
- **MCP config rules** — `MCP-001`–`MCP-005`; home-dir configs only with `scan --include-home`
- **Runtime extras** — RASP sink hooks, virtual patches, honeytokens, response DLP
- **Platform** — threat-model sketch, local dashboard, incremental scan, `dev` save loop
- **Reports** — scan diff, SARIF/audit/Semgrep ingest, policy file, PR summary, GitHub/GitLab/JUnit CI annotations, compliance mapping, SPDX SBOM
- **IaC** — short ruleset for GitHub Actions, Terraform, Kubernetes, docker-compose
- **Remediation agent** — localhost mock GitHub API and local git only
- **Extra scan classes** — ReDoS, deserialization, XXE, upload, cookies, CSRF, mass assignment, timing compare, hash cost, GraphQL, trust-proxy, IDOR hints, extra SAST sinks, framework taint (Next/Nest/Hono/Koa), crypto v2, Electron, vendored JS, template injection, webhooks, session fixation, log secrets, Next.js boundary, browser JS, TLS, credential files, git-history and bundle secrets, live credential checks
- **Host** — Linux OpenSSH exposure report only

`SECURITY.md` is the vulnerability-reporting policy (private GitHub advisories, 7-day response, in-scope CLI/library/runtime). It does not add scan features.

## Dev checks (not packed)

These scripts stay off unless their flag is `1`. They do not change a default scan. A parked line is a stop the spec requires.

### Holdout rows (`FULLSHIELD_EXPERIMENTAL_HOLDOUTS`)

- Ten rows, each `status: untouched`, `reviewed: false`, empty `firstRunDate`, an https repo, and a 40-hex commit pin
- A results file for that name in the same commit fails
- `tuning` and `seen` fail
- Duplicate names fail
- Placeholder names (`placeholder`, `todo`, `tbd`, `changeme`, `unnamed`, `fixme`, `repo`, `holdout`) fail
- No names supplied: parked. This tree does not invent repos and does not edit `bench/holdouts.json`

### Unsoundness register (`FULLSHIELD_EXPERIMENTAL_UNSOUNDREG`)

- Every kind in the phase 271 enum has a matching heading, and every heading is a kind
- The opening sentence says exhaustion over-approximates in sound mode and does not drop facts silently
- The doc does not say the engine is sound, and `reviewed` stays false
- A heading with no reason line fails as `reason absent (human-owned)`. The checker does not write the reason
- `--repo` reads `src/phases/p271.ts` and `docs/unsoundness.md`. A run with no file still parks

### Release provenance shape (`FULLSHIELD_EXPERIMENTAL_PROVSHAPE`)

- The workflow text must already name `subject`, `buildType`, and `isolation`
- `subject` must be non-empty, `buildType` must be an https URL, and `isolation` must be `hosted`, `self-hosted`, or `sandboxed`
- A deleted `subject` fails
- The real publish workflow is missing those fields, so a `--repo` run parks and names them. The checker does not insert a field

### SBOM signature (`FULLSHIELD_EXPERIMENTAL_RELEASESIGN`)

- The tag publish job writes a CycloneDX file and runs `phase493-releasesign.mjs --sbom-sign`
- The key comes from `secrets.SBOM_SIGN_KEY`. The script does not create it, print it, or upload it
- A release job without the secret fails. A pull-request job without it does not
- `continue-on-error` on the sign step fails the lint
- The dry run signs with a fixture key and does not publish

### Hard-dependency guard (`FULLSHIELD_EXPERIMENTAL_DEPMIN`)

- The allow list is empty
- A scratch `leftpad` dependency fails
- A peer without `optional: true` fails
- This package already has hard dependencies, so a check of `package.json` parks, names each one, and records that later edits are R1. This phase does not delete them

### Release-build pins (`FULLSHIELD_EXPERIMENTAL_BUILDPIN`)

- An action without a 40-hex SHA fails, and `@vN` is called out as a floating tag
- `npm install` fails. `npm ci` must include `--ignore-scripts`
- Node must be `x.y.z`. npm must be pinned beside `setup-node`
- The repo workflows still fail those sub-points. The lint parks and does not rewrite them. Action SHAs already in the files are not treated as verified by this tool
