# FullShield features (1.7.0)

Inventory of what this tree ships, plus the behaviors 1.7.0 adds. Default use is a Node.js/TypeScript scan that detects, classifies, reports, notifies, suggests fixes, and can gate CI. Experimental features stay off unless their flag is set to `1`.

1.7.0 deepens the rules that already ship. It does not replace those rules, and it does not make a shipped rule go silent. Default `scan --json` changes only for the two Stable sinks below, and only in a file that uses that sink shape. An app that does not use them stays the same. The other deeper checks stay off until `FULLSHIELD_EXPERIMENTAL_DEEP` is `1`. All of them ship in the published npm package. `clean-app` stays at 0 findings with the new flag off and on. A `--repo` run uses local fixtures and does not park.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (1.7.0)

The SQL, command, XSS, SSRF, path, redirect, JWT, and prototype rules keep every match they have today. 1.7.0 adds the sink shapes those rules still skip. No check contacts a registry, opens a network connection, executes the scanned file, or spawns a process.

### Stable (default scan, no flag)

Default `scan --json` gains a finding only in a file that uses one of these sink shapes. An app that does not use them stays the same. No new rule id. The 1.6.0 sqlite, Bun, Deno, and library-eval matches stay as they are.

- **Tagged-template SQL on the SQL rule** — `SAST-SQLI-001` also fires when a tagged template interpolates request data and the tag is `sql`, or the tag is a member named `sql`, and the file imports `postgres`, `mysql2`, `@databases/pg`, `slonik`, or `drizzle-orm`. A template with no interpolation does not fire. A tag that is not `sql` does not fire. A `query` or `execute` call that uses `?` or `$1` placeholders, with the request value passed as a separate bound argument, stays silent, including the parameterized query in `clean-app`. It refuses to open a database and refuses to execute the file. `clean-app` stays at 0 findings.

- **execFile command path on the command rule** — `SAST-CMDI-001` also fires for `execFile` and `execFileSync` when the command path, the first argument, is request data. A string-literal command path does not fire, even when a later argument is request data. `execFile('ping', ['-c', '1', host])` in `clean-app` stays silent. `shell: true` is not required for this case. Existing `exec`, `spawn`, Bun, and Deno matches stay as they are. It refuses to spawn a process. `clean-app` stays at 0 findings.

### Experimental (`FULLSHIELD_EXPERIMENTAL_DEEP`)

- **Deeper checks on the existing rules** — `scan --experimental-deep` sets the flag. With the flag on, the rules below gain the extra matches. The rule id does not change. Flag off: these extra matches are not loaded, and default `scan --json` is unchanged. A string literal does not fire. It refuses to fetch a URL, refuses to read a file, refuses to redirect, refuses to verify a token, and refuses to merge an object. `clean-app` stays at 0 findings with the flag on.

  - `SAST-XSS-001` also fires for `end` when the argument is request data and the argument or the file contains an HTML tag. `send` and `write` stay as they are. `res.status(401).end()` with no argument stays silent.
  - `SAST-SSRF-001` also fires when `http.request` or `https.request` is passed an options object whose `hostname`, `host`, `href`, or `path` is request data. A literal hostname does not fire. `fetch` and `axios` stay as they are.
  - `SAST-PATH-001` also fires for `Bun.file`, `glob`, and `opendir` when the path is request data. A literal path does not fire. The existing `readFile` and `sendFile` matches stay as they are.
  - `SAST-REDIRECT-001` also fires for `location` when the target is request data. `redirect` stays as it is. A target that is only a string literal, including the `/home` or `/` choice in `clean-app`, does not fire.
  - `SAST-JWT-001` also fires when `jwt.verify` is called with no `algorithms` option, with an empty `algorithms` array, or with an `algorithms` value that is not an array literal. A literal array that does not include `none`, including `['HS256']` in `clean-app`, does not fire. The existing `decode` and `none` matches stay as they are.
  - `SAST-PROTO-001` also fires for `Object.assign` and for a call named `assign` when one argument is request data and the file does not compare a key to `__proto__`. `merge`, `defaultsDeep`, and `deepMerge` stay as they are. A local function named `merge`, including the one in `clean-app`, does not fire. A literal object does not fire.

### Experimental (`FULLSHIELD_EXPERIMENTAL_RSC`)

- **React Server Components versions** — `scan --experimental-rsc` sets the flag. With the flag on, `DEPS-RSC-001` fires when a lockfile resolves `react-server-dom-webpack`, `react-server-dom-parcel`, or `react-server-dom-turbopack` to `19.0.0`, `19.1.0`, `19.1.1`, or `19.2.0` (CVE-2025-55182). Any other version does not fire. It reads `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and `bun.lock` that are already in the tree. It refuses to contact the registry and refuses to install a package. A project with no lockfile does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_COOLDOWN`)

- **Dependency release-age gate** — `scan --experimental-cooldown` sets the flag. With the flag on, `CONFIG-COOLDOWN-001` fires when `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, or `bunfig.toml` is present and its release-age gate is missing or shorter than three days. npm `min-release-age` is days, pnpm `minimumReleaseAge` is minutes, yarn `npmMinimalAgeGate` is a duration, and bun `minimumReleaseAge` is seconds. A value of `3` in the wrong unit, so the real wait is under three days, fires, and the finding names the unit. A gate of at least three days does not fire. A project that has only `package.json` and a lockfile, and none of those four config files, does not fire. It refuses to install a package and refuses to contact a registry. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT`)

- **Import-time worm files** — `scan --experimental-import-implant` sets the flag. With the flag on, `SUPPLY-IMPLANT-001` fires when a package inside the scanned directory (a committed file or a `node_modules` tree that is already on disk) contains `setup_bun.js` or `bun_environment.js`, or a `preinstall`, `install`, or `postinstall` script that names either file. It does not ship a catalog of compromised versions and it does not read the npm cache. A package whose files are not already on disk is skipped. It refuses to fetch a tarball, refuses to install a package, and refuses to execute a script. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_VERINFLATE`)

- **Inflated dependency versions** — `scan --experimental-ver-inflate` sets the flag. With the flag on, `DEPS-VERINFLATE-001` fires when a lockfile already in the tree resolves a package to a version whose major is `9999` or greater, or whose patch is `999` or `9999` (the flooding-dropper shape). A normal version such as `1.2.3` does not fire. It refuses to contact a registry. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_AGENTRULES`)

- **Agent instruction files** — `scan --experimental-agent-rules` sets the flag. With the flag on, these files are scanned: `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.cursor/rules/**`, `.windsurf/rules/**`, and `SKILL.md` under `.cursor/`, `.claude/`, or `.agents/`. `AGENT-UNICODE-001` fires on a Unicode Tag character (U+E0001–U+E007F), a zero-width character, or a bidi override. `AGENT-INJECT-001` fires on an instruction phrase `ignore previous` or `do not tell the user`. `AGENT-EXFIL-001` fires when the file tells the agent to send `.env`, a token, or a secret to an `http` or `https` URL. `AGENT-SHELL-001` fires when the file tells the agent to launch `claude`, `codex`, or `gemini` with `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, or `--yolo`. A short guideline with none of those does not fire. It refuses to follow the instructions and refuses to fetch a URL. Flag off: this module is not loaded and default `scan --json` does not include these rules. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_AGENTSPAWN`)

- **Coding-agent bypass spawn** — `scan --experimental-agent-spawn` sets the flag. With the flag on, `SAST-AGENTSPAWN-001` fires when `child_process`, `Bun.spawn`, `Bun.spawnSync`, or `Deno.Command` launches `claude`, `codex`, or `gemini` with `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, or `--yolo`. Launching one of those programs without that flag does not fire. It refuses to spawn the process. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_MCPPOISON`)

- **MCP metadata attacks** — `scan --experimental-mcp-poison` sets the flag. With the flag on, a local MCP config gains three rules beyond `MCP-001`–`MCP-005`. `MCP-006` fires when a tool or prompt schema or description asks the user for a password, token, secret, or API key. `MCP-007` fires when a tool schema default is a shell command or contains `ignore previous`. `MCP-008` fires when two servers in the same config file declare the same tool name. One server with literal descriptions does not fire. `MCP-001`–`MCP-005` stay on `FULLSHIELD_EXPERIMENTAL_MCPCFG` and are not changed. It refuses to connect to a server. Flag off: this module is not loaded and default `scan --json` does not include `MCP-006`–`MCP-008`. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_VITEFS`)

- **Vite filesystem exposure** — `scan --experimental-vite-fs` sets the flag. With the flag on, `CONFIG-VITEFS-001` fires when a Vite config sets `server.fs.strict` to false, or sets `server.fs.allow` to a filesystem root (`/`, a drive root, or a path that is only that root). A config that leaves `server.fs` unset does not fire. It refuses to start Vite and refuses to contact a registry. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_HOSTPOISON`)

- **Host-header links** — `scan --experimental-host-poison` sets the flag. With the flag on, `SAST-HOST-001` fires when `Host` or `X-Forwarded-Host` (`req.headers.host`, `req.headers['x-forwarded-host']`, or `req.get` of those names) is copied into an absolute URL that is passed to a redirect, a `Location` header, or a mailer. A fixed host string does not fire. `req.hostname` by itself does not fire. It refuses to send mail and refuses to open a connection. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_MARKUP`)

- **Markdown HTML sinks** — `scan --experimental-markup` sets the flag. With the flag on, `SAST-MARKUP-001` fires when `markdown-it` is constructed with `html: true`, or `marked` is called, and the markdown input is request data (`req.query`, `req.body`, `req.params`, `req.headers`, or a binding of those). A string-literal markdown body does not fire. It refuses to render the markdown. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_TRUSTHOST`)

- **Auth.js trustHost** — `scan --experimental-trust-host` sets the flag. With the flag on, `SAST-TRUSTHOST-001` fires when a NextAuth or Auth.js config sets `trustHost` to `true`. `trustHost: false`, or a config that omits `trustHost`, does not fire. It refuses to perform a login. Flag off: this module is not loaded and default `scan --json` does not include this rule. `clean-app` stays at 0 findings with the flag on.

### Unchanged from 1.6.0

- **SQLite exec/prepare**, **Bun and Deno shells**, and **mathjs / expr-eval / vm2 evaluate** — still part of the default scan. No new rule id.
- **React Server Components versions, release-age cooldown, import-time worm files, inflated versions, agent instruction files, coding-agent bypass spawn, MCP metadata attacks, Vite filesystem exposure, host-header links, markdown HTML, and Auth.js trustHost** — still experimental, still off until their own flag is `1`.
- **Field and closure taint**, **ORM raw queries and shell variants** — still part of the default scan. Their old flags stay accepted and do not turn them off.
- **LDAP injection**, **reflected CORS origin**, and **diff scan** — still experimental, still off until their own flag is `1`.

## Stable (on by default)

### Scan modules

`fullshield scan` runs all four:

- **Dependencies** — OSV advisories with reachability (`reachable`, `imported-not-called`, `reachable-via-dependency`, `not-imported`, `reachability-unknown`), dev-only notes, lockfile deprecation, typosquat names, malicious `MAL-` advisories (always critical), missing lockfile.
- **Secrets** — AWS, Stripe, GitHub, Slack, Google, AI keys, PEM keys, DB URLs with passwords, hardcoded JWT secrets, committed `.env`.
- **SAST** — SQL/NoSQL injection (including `node:sqlite`, `bun:sqlite`, and a `sql` tagged template from postgres, mysql2, `@databases/pg`, slonik, or drizzle-orm), command injection (including Bun and Deno shells, and `execFile` / `execFileSync` when the command path is request data), path traversal, `eval` / `new Function` / `vm` / `mathjs` / `expr-eval` / `vm2`, SSRF, open redirects, JWT `decode` / `none`, weak crypto, prototype pollution, XSS, missing auth middleware (low confidence), plus a basic comment-phrase check (`AI-INJECT-001`).
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
- **MCP config rules** — `MCP-001`–`MCP-005`; home-dir configs only with `scan --include-home`. `MCP-006`–`MCP-008` need `FULLSHIELD_EXPERIMENTAL_MCPPOISON`
- **Runtime extras** — RASP sink hooks, virtual patches, honeytokens, response DLP
- **Platform** — threat-model sketch, local dashboard, incremental scan, `dev` save loop
- **Reports** — scan diff, SARIF/audit/Semgrep ingest, policy file, PR summary, GitHub/GitLab/JUnit CI annotations, compliance mapping, SPDX SBOM
- **IaC** — short ruleset for GitHub Actions, Terraform, Kubernetes, docker-compose
- **Remediation agent** — localhost mock GitHub API and local git only
- **Extra scan classes** — ReDoS, deserialization, XXE, upload, cookies, CSRF, mass assignment, timing compare, hash cost, GraphQL, trust-proxy, IDOR hints, extra SAST sinks, framework taint (Next/Nest/Hono/Koa), crypto v2, Electron, vendored JS, template injection, webhooks, session fixation, log secrets, Next.js boundary, browser JS, TLS, credential files, git-history and bundle secrets, live credential checks
- **This version, off until the flag is `1`** — `scan --experimental-deep` (`FULLSHIELD_EXPERIMENTAL_DEEP`): `end` XSS, `http.request` option objects, `Bun.file` / `glob` / `opendir`, `location` redirects, `jwt.verify` without a literal algorithm list, and `Object.assign` / `assign`. The 1.6.0 checks stay on their own flags: RSC lockfile versions, release-age gate, import-time worm files, inflated versions, agent instruction files, coding-agent bypass spawn, MCP metadata attacks, Vite filesystem exposure, host-header links, markdown HTML, Auth.js `trustHost`
- **Host** — Linux OpenSSH exposure report only

`SECURITY.md` is the vulnerability-reporting policy (private GitHub advisories, 7-day response, in-scope CLI/library/runtime). It does not add scan features.

## Dev checks (not packed)

These scripts stay off unless their flag is `1`. They do not change a default scan. A parked line is a stop the spec requires. 1.7.0 does not add a dev check.

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
