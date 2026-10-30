# FullShield features (3.5.3)

## 3.5.3

Source: the terminal and the Markdown report describe the same scan and disagree once the list is longer than the screen. This is a patch on 3.5.2. It adds no command, no CLI option, no `rules/*.md` file, no package export, and no new `FULLSHIELD_EXPERIMENTAL_*` flag. `--all`, `--markdown`, and `--fail-on` already exist. JSON, SARIF, the exit code, finding fields, severity, and reachability stay as they are. `stableChange: false` for `scan --json`. HTML is unchanged. `.github/workflows` is not edited.

`docs/demo.md` is replaced from a real `scan` of `test/fixtures/vulnerable-app` after the printer exists. It is not written by hand to match a wish.

The continuation of this chat approves the assertion edits in these existing tests, because they pin the old console sentences: `test/unit/reporters/reporters.test.ts`, `test/unit/reporters/phase47-console.test.ts`, `test/unit/cli/phase44-doctor.test.ts`, and `test/unit/modules/secrets/phase82-secret-check.test.ts`. No other existing test, fixture, or `expected-findings.json` is edited.

- **Counts.** The first summary line and the footer use the same totals. A severity header uses the real total, such as `HIGH (21)`, and then says how many of those rows are on screen. The printed slice is not the header count.
- **Decision.** When a finding is at or above the effective `failOn`, the first screen says `fail` and names that severity and how many findings are at or above it. Otherwise it says `pass`. The process exit code is unchanged.
- **Do this first.** At most three lines, in this order: a malicious package, then one reachable critical or high dependency that has a version bump, then one committed secret. A missing kind is skipped. The upgrade sentence and the unused-package sentence are inside this block. They are not printed above the list.
- **Terminal grouping.** The same rule id prints once, with the count and each location under it. An existing dependency group stays one package line. The terminal fix is one short action. A secret says to rotate it and load it from the environment. A SAST hit says the action, and the CWE link stays on the docs line. The long remediation stays in the rule doc and in the report.
- **More.** The overflow line points at `--all` and `--markdown report.md`. `--json` stays the machine format.
- **Markdown.** `renderMarkdownReport` uses that same opening, including the fail line and the three-item list. A scheduled `fullShieldReport/*.md` uses this function, so it gets the same opening. Inside a severity, a rule that fires more than once has one heading and every location. Each finding keeps where, reachability, snippet, issue, fix, trace, and the docs link.

## 3.5.1 and 3.5.2

Two patches on 3.5.0. Neither adds a command, a CLI option, a `rules/*.md` file, a package export, or a new `FULLSHIELD_EXPERIMENTAL_*` flag. Both use the existing flag `FULLSHIELD_EXPERIMENTAL_SECTIONG`. The flag stays off unless the value is `1`.

Flag off, default `scan --json` findings stay byte-identical to 3.5.0. `clean-app` stays at 0 findings on the default scan, and at 0 with the flag on. `stableChange: false`. No new host. No container or OS package scan. No eBPF. No second language. No letter grade. No recall number. No company quote. No claim that a process prevents an attack. `.github/workflows` is not edited. Scanned code is not executed. Project tests are not run. Severity is `low` unless the line says `medium`. Source of these findings is `rule`.

Already in the tree, so these versions do not add a second finding for them: H2, H3, H4, H6, H25, H52, the GitLab half of H45, the open `images.remotePatterns` half of H19, the package-name half of H1, and the Terraform `public-read` half of H35.

## 3.5.1

Source: the unfinished package, lockfile, and framework lines in section H. One local check each. A positive fixture finds it. A negative fixture does not.

- **H1.** A lockfile URL or a JavaScript string contains U+202E or U+200B: one finding, severity `medium`. An ASCII lockfile URL is not. A dependency name is left to `DEPS-BIDI-001`.
- **H5.** `package-lock.json` and `yarn.lock` or `pnpm-lock.yaml` both exist and name the same package at two versions: one finding. One lockfile is not.
- **H7.** A file under `patches/` assigns `req.body` or `req.query` into a call that contains `query(`, `exec(`, or `send(`: one finding, severity `medium`. A patch that only changes a version string is not.
- **H8.** `files` in `package.json` or a line in `.npmignore` that is not a negation names `.env`, `id_rsa`, or `.github`: one finding, severity `medium`. A `files` list of `dist` only is not.
- **H9.** A `package.json` whose `name` is also listed under `workspaces` has no `"private": true`: one finding. `"private": true` is not.
- **H10.** A `preinstall`, `install`, or `postinstall` script contains `curl` or `wget`: one finding, severity `medium`. The script is not executed. A script that only runs `node` is not.
- **H11.** A script or config fetches `http://` or `https://` and the same file has no `integrity` and no `sha256`: one finding. A file that contains `sha256` is not.
- **H12.** A `start`, `preinstall`, `install`, or `postinstall` script contains `--require` or `NODE_OPTIONS`: one finding. A script that only runs `node server.js` is not.
- **H13.** `engines.node`, and `.nvmrc` or `.node-version` when that file exists, name different major versions: one finding. The same major is not. No CI file is read.
- **H14.** A production `.js` file imports a name that `package.json` lists only under `devDependencies`: one finding. A dependency listed under `dependencies` is not.
- **H15.** `@types/<name>` and `<name>` are both in the lockfile and their major versions differ: one finding. The same major is not.
- **H16.** `req.` is passed to `.raw(`, `sequelize.query(`, or `createQueryBuilder(` in a file that also contains `knex`, `sequelize`, or `typeorm`: one finding, severity `medium`. A placeholder `$1` is not.
- **H17.** `req.` appears in the same file as `$where` or `mongoose` and `.where(`: one finding, severity `medium`. A literal query with no `req.` is not.
- **H18.** `socket.on('message'` or `socket.on("connection"` passes that callback value to `query(`, `exec(`, or `send(`: one finding. A handler that sends a literal is not.
- **H19.** A `redirects` or `rewrites` entry copies `req.query` into `destination` or `source`: one finding, severity `medium`. A fixed destination is not. Open `images.remotePatterns` stays on its existing check.
- **H20.** A file contains `matcher` and `/:path*`, or `'use server'` and `searchParams` and no `origin`: one finding. A matcher of `/account` only is not.
- **H21.** A file contains `loader` or `action` and `LoaderFunction` or `astro` and passes `request.` to `query(` or `send(`: one finding. A literal return is not.
- **H22.** A file contains `fastify` and `.post(` or `.put(` and `request.body` and `query(` and does not contain `schema`: one finding. A route with `schema` is not.
- **H23.** A file contains `graphql` and `introspection: true`, or `graphql` and no `depthLimit`, and the path does not include `test`: one finding. A test path is not.
- **H24.** A file contains `.listen(` and does not contain `helmet`: one finding. A file that calls `helmet()` is not.
- **H26.** `express.json(` with no `limit`, or a `limit` whose digits are greater than `100`, or `bodyLimit` whose digits are greater than `100`: one finding. `limit: '100kb'` is not.
- **H27.** A file contains `swagger`, `graphql-playground`, or `'/metrics'` and does not contain `auth`: one finding. A file that contains `auth` is not.

## 3.5.2

Source: the unfinished auth, CI text, and output lines in section H. Same flag. Same limits. Built only after 3.5.1 is tagged.

- **H28.** A redirect contains `oauth` or `authorize` and does not contain `state`, or a token request contains `code` and does not contain `verifier`: one finding, severity `medium`. A redirect that contains `state` is not.
- **H29.** `res.redirect` is called with `req.query.next` or `req.query.return` and the file has no array literal: one finding, severity `medium`. A fixed path is not.
- **H30.** `secret:` or `jwt.sign` is followed by a string literal: one finding, severity `medium`. `process.env` is not.
- **H31.** One statement contains `SameSite=None` or `sameSite: 'none'` and does not contain `secure`: one finding, severity `medium`. A statement that also contains `secure` is not. A path that includes `test` is not.
- **H32.** `createHash('md5'` or `createHash('sha1'` or `createHash("md5"` or `createHash("sha1"` appears in a file that also contains `password`: one finding, severity `medium`. `bcrypt` is not this finding.
- **H33.** A file contains `email` or `password` and `.update(` and does not contain `currentPassword` or `req.session`: one finding. A file that reads `req.session` is not.
- **H34.** `getSignedUrl` or `presign` appears and the file contains neither `expiresIn` nor `Expires`: one finding. A call that contains `expiresIn` is not.
- **H35.** Application source contains `public-read` or `public-read-write`: one finding, severity `medium`. Terraform text stays on its existing check.
- **H36.** A workflow line contains `run:` and `${{ github.event.`: one finding, severity `medium`. A `run:` line with no `${{` is not.
- **H37.** A `uses:` value contains `/` and does not end in 40 hex characters, and is not `actions/checkout` or `actions/setup-node`: one finding. A 40-hex pin is not.
- **H38.** The same workflow job contains `uses:` of a name other than `actions/checkout` or `actions/setup-node`, and `secrets.`: one finding, severity `medium`. A job with no `secrets.` is not.
- **H39.** A workflow contains `persist-credentials: true` and `pull_request`: one finding, severity `medium`. `persist-credentials: false` is not.
- **H40.** A workflow contains `pull_request:` and `contents: write` or `id-token: write`: one finding, severity `medium`. A workflow whose only trigger is `push:` is not.
- **H41.** `.gitignore` or `.dockerignore` exists and does not contain `.env`: one finding. A file that contains `.env` is not. A missing ignore file is not.
- **H42.** A Dockerfile line starts with `ARG`, `ENV`, or `COPY` and contains `.env`, `id_rsa`, or `.npmrc`: one finding, severity `medium`. A `COPY` of `package.json` is not.
- **H43.** A compose file contains `ports:` and `PASSWORD` and a quoted literal: one finding, severity `medium`. `PASSWORD: ${DB_PASSWORD}` is not.
- **H44.** A workflow contains `npm publish` and `NODE_AUTH_TOKEN` and does not contain `id-token:`: one finding, severity `medium`. A workflow with `id-token:` is not. This repo's workflows are not edited.
- **H45.** If `sectionh-format.txt` exists, one finding whose message is JSON `{reviewdog}` of `{ruleId, file, line, severity}` from the input findings. GitLab output stays on the existing check. No second scanner.
- **H46.** `docs/scan-result.schema.json` exists and contains `"schemaVersion"`. No new network host. The schema describes the current scan JSON fields and does not add a required field.
- **H47.** If `sectionh-doctor.txt` is a number and `sectionh-osv-cache.json` is older than that many days, one finding names the age. A missing cache file is one finding. Nothing is fetched. `doctor` gains no option.
- **H48.** If `sectionh-relative.txt` exists, one finding whose message is the relative path of each input finding. Absolute prefixes are omitted. Default SARIF and JSON are unchanged.
- **H49.** If `sectionh-mask.txt` exists, a finding message that contains a line from that file is reported with that line replaced by `[masked]`. The mask file is not printed. Default reports are unchanged when the file is absent.
- **H50.** If `sectionh-report.txt` exists, write `sectionh-report.json` with mode `0600` and the input rule ids. Other report writers are unchanged.
- **H51.** If `sectionh-lockonly.txt` exists, the section H source walk does not read `.js`, `.jsx`, `.ts`, or `.tsx`. Lockfile checks in this version still run. No new command.
- **H53.** If `sectionh-policy.json` is `{failOn, ruleIds}`, one finding lists the input rule ids that are in `ruleIds`. Nothing is written over the project.
- **H54.** If `sectionh-epss.json` is `{ruleId: number}`, one finding's message is `ruleId score` using that local number, severity, and `unspecified` when reachability is missing. No new host. No learned model.
- **H55.** If `sectionh-bumps.json` is an array of `{name, from, to, override}`, the finding message prefers a row with `override: true`, then a `to` that changes only the patch, and says which one it picked. No install.
- **H56.** If `sectionh-delta.json` has `{from, to}` script, license, or `native` fields that differ, one finding names the field that changed. Scripts are not run.
- **H57.** If `sectionh-offline.txt` exists and `sectionh-osv-cache.json` is missing, throw before a scan write. Do not fetch the file.
- **H58.** `templates/self-scan.md` says this repo is scanned with the default rules. `.github/workflows` is not edited and does not gain a self-scan job.
- **H59.** A finding whose file is under `dist/` and whose directory contains a `.map` file gains a message with that map name. No map file adds nothing.
- **H60.** Not built. No telemetry, no phone-home, no second language, no container CVE database, and no prevention claim.

## 3.5.0

Inventory of what **3.5.0** adds. Source: section G below, G1–G51. This is a minor on 3.4.2. It adds one flag, `FULLSHIELD_EXPERIMENTAL_SECTIONG`. It adds no command, no CLI option, no `rules/*.md` file, and no package export.

The flag is off unless the value is `1`. Flag off, default `scan --json` findings stay byte-identical to 3.4.2 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. `clean-app` stays at 0 findings on the default scan, and at 0 with the flag on for that fixture. A `--repo` run does not park. `stableChange: false`.

No new host. No container or OS package scan. No eBPF. No second language. No letter grade. No recall number. No company quote. No claim that a process prevents an attack. `.github/workflows` is not edited. Scanned code is not executed. Project tests are not run.

With the flag on, each item below is a local static check. A positive fixture finds it. A negative fixture does not. Severity on these findings is `low` unless the line says `medium`. None of them is a default-scan finding.

- **G1.** A value assigned from `req.body` in one file is passed to `res.send` or `res.end` in a second file that the first file imports by a string literal. Same-file `SAST-STORED-001` is unchanged.
- **G2.** A parse cache may be used only while the flag is on, and only when the cached findings equal the uncached findings on the fixture. The cache is not on by default. Flag off does not cache.
- **G3.** A file with `'use server'` that reads `searchParams` and sends it as HTML is one finding. A file that encodes the value first is not.
- **G4.** An `@Get` or `@Post` handler with no `@UseGuards` in that file is one finding. A handler with `@UseGuards` is not.
- **G5.** `publicProcedure` that reads an `id` and calls `update` or `delete` in the same file is one finding. A `protectedProcedure` is not.
- **G6.** A string argument to `$queryRawUnsafe` or `$executeRawUnsafe` that contains request data is one finding. A tagged `$queryRaw` template is not.
- **G7.** ReDoS, XXE, deserialization, CSRF, cookies, mass assignment, and GraphQL stay on their existing flag. This version does not turn that flag on and does not promote them.
- **G8.** A local OpenAPI file lists `/admin` and no source file contains the text `/admin`: one finding. If a source file contains `/admin`, no finding.
- **G9.** A method whose name contains `grpc` passes `request.` into `query`, `exec`, or `fetch` in that file: one finding. A literal query is not.
- **G10.** A `message` callback argument is passed to `res.send` in that file: one finding. A literal string sent from that callback is not.
- **G11.** A `bull` or `sqs` job handler passes `job.data` or `body` to `exec` or `query` in that file: one finding. A handler that only logs a literal is not.
- **G12.** A response that sets both `Content-Length` and `Transfer-Encoding` from request data is one finding. A response that sets only a literal content type is not.
- **G13.** Request data written with `save` in one file is concatenated into a SQL string in a second file imported by a string literal: one finding, severity `medium`. A placeholder query is not.
- **G14.** No new IDOR finding. `SAST-IDOR-001` stays experimental and still does not fail CI. `req.params.id` stays off the default high gate.
- **G15.** An `app.post` or `app.put` handler with no `req.user`, `req.session`, or `auth` in that file is one finding. A handler that reads `req.user` is not.
- **G16.** `entry.path` or `entry.fileName` that contains `../` passed to an extract call is one finding, severity `medium`. A literal name `readme.txt` is not.
- **G17.** `yaml.load` of request data with `DEFAULT_FULL_SCHEMA` or `unsafeLoad` is one finding, severity `medium`, only from this flag. The older classes flag is unchanged. `JSON_SCHEMA` is not a finding.
- **G18.** `redirect_uri` or `redirect` taken from `req.query` with no allowlist array in that file is one finding, severity `medium`. A fixed URL is not.
- **G19.** Request data copied into a property named `system`, `prompt`, or `messages` is one finding. A literal prompt is not.
- **G20.** A tool `description` string that contains `ignore previous` or `child_process` is one finding, severity `medium`. A literal description that contains neither is not.
- **G21.** A workflow file that contains `pull_request_target` and `actions/checkout` of the pull-request head is one finding, severity `medium`. A workflow with neither is not. This does not edit `.github/workflows` in this repo.
- **G22.** A Dockerfile whose text has no `USER`, or has `USER root`, is one finding. `USER node` is not. A Kubernetes manifest with `privileged: true`, `hostPath`, or `hostNetwork: true` is one finding. This does not scan image contents or OS packages.
- **G23.** A name present in a local SBOM JSON and absent from a local `node_modules` listing, or the reverse, is one finding. No package is installed.
- **G24.** Given a list of changed paths, the check returns the workspace directory that contains each path. It does not skip the rest of the scan.
- **G25.** A local rules file with a fixture string that is not found by its own pattern is one finding. A pattern that matches its fixture is not. Rules are not downloaded.
- **G26.** A pre-commit path list that includes a path outside the project, or a path under the home directory, is refused and nothing is scanned. Paths inside the project are kept.
- **G27.** The same findings can be printed as GitLab SAST JSON and Bitbucket annotations. The finding keys are the ones already produced. No second scanner runs.
- **G28.** Before one safe fix is written, a copy of that file is saved next to it. If a re-scan of the new text still contains the finding, the copy is written back. Project tests are not run.
- **G29.** Two safe fixes in one list are applied in order. An unsafe fix in that list throws and writes nothing.
- **G30.** A literal `import("pkg")` counts as an import of `pkg`. `import("./" + name)` does not.
- **G31.** Nothing is built. Function reachability is not invented. Import-level reachability stays as it is.
- **G32.** One finding that already has a trace with a file and a line on the first and last step prints a Mermaid flowchart of those two nodes. A finding with no trace prints nothing.
- **G33.** A stored SQL fingerprint equal to the fingerprint of a line that contains `.query(` makes that line a finding. An empty fingerprint adds nothing. The default scan does not read the fingerprint.
- **G34.** A confirm plan names `127.0.0.1` only. A row with status `unconfirmed` is not a pass. No timer is registered and no request is sent by this check.
- **G35.** A local OSV JSON array is filtered to ids whose package name is also imported from `express` paths in a local file list. Nothing is fetched. The output is not a published CVE count.
- **G36.** Not claimed. npm, pnpm, yarn, and bun stay `not claimed` in `docs/compatibility.md`. No CI job is added.
- **G37.** Not claimed. Express, Fastify, Nest, and Next stay `not claimed`. No CI job is added.
- **G38.** `templates/stranger-check.md` stays a template. It is not copied into `.github/workflows`.
- **G39.** `templates/tutorial/app.js` contains one planted `res.send` of request data and a checklist comment that names the rule note. The planted text is not a real secret. The file does not suppress findings.
- **G40.** A local scope list includes `@acme/widget`, and a lockfile resolves that name from `registry.npmjs.org`: one finding, severity `medium`. A resolution from another host string is not. Nothing is fetched.
- **G41.** The scope list is a file in the project. A missing file adds no finding and throws nothing.
- **G42.** An exception record with `owner`, `reason`, `expires`, `ruleId`, and severity `critical` is printed as one audit line. A record missing `owner` is refused. Nothing is sent to GitHub.
- **G43.** SARIF built from findings minus a baseline file contains only the new rule ids. A finding whose rule id is in the baseline is omitted.
- **G44.** A user-controlled URL whose host is `169.254.169.254`, `2852039166`, or `[::ffff:169.254.169.254]` is one finding, severity `medium`. A URL to `example.com` is not.
- **G45.** One sentence in `docs/vs-npm-audit.md` says a static scan cannot see a DNS answer that changes. No DNS lookup is added.
- **G46.** A handler sets `Cache-Control` to a public value and copies `req.headers.cookie` into the body: one finding, severity `medium`. A handler that does not read the cookie is not.
- **G47.** A redirect or mail body contains both the word `reset` and `token=` plus request data: one finding, severity `medium`. A fixed path `/reset` with no token is not.
- **G48.** One file contains two different literals, `no such user` and `bad password`: one finding. One shared literal `invalid login` is not.
- **G49.** An `app.post('/login'` handler with no `rateLimit` in that file is one finding. A handler that calls `rateLimit` is not. This finding does not use severity `high`.
- **G50.** A workflow with `id-token: write` and `actions/checkout` of an untrusted ref is one finding, severity `medium`. A workflow with `id-token: write` and a checkout of the branch only is not.
- **G51.** Not built. No container CVE database, no eBPF, no Python or other language in this package, no letter grade, no recall number, no company quote, and no prevention claim.

## Planning notes

The sections below are planning notes. Section G is the source of the 3.5.0 inventory above. Section H is the source of the 3.5.1 and 3.5.2 inventories. The published tree stays 3.5.0 until 3.5.1 is built. [stability.md](stability.md) and `SECURITY_SCANNER_SPEC.md` still win over this file where they disagree.

## Honest take

“Top 1 npm security package” is not won by cloning Snyk + Sonar + `npm audit`. Those win on trust, integrations, and sales, not feature count. FullShield’s real wedge is already Node/TS backend + reachability + one CLI. Copying every enterprise checkbox dilutes that.

That market blurb is roughly right: early/niche, not mainstream. Using it today is fine for Node backends that want one local tool; it is not a Snyk replacement for large enterprises yet.

## What FullShield already has (and competitors often split)

| Area | You already ship |
| --- | --- |
| Deps + reachability | OSV + reachable / not-imported (headline) |
| SAST | Injection, XSS, SSRF, secrets, config |
| Supply chain | Malicious OSV, typosquat, lock hygiene |
| Runtime | Express/Fastify/Koa/Hono monitor + experimental RASP |
| Fix / CI | `fix`, `--fail-on`, SARIF, SBOM |
| Extras (mostly experimental) | Policy, VEX, MCP, LLM rules, DLP, host SSH |

## What others provide that you could add

List only — not committing to build. Each item has: **today**, **basic add**, **advanced add**, and **risk / SPEC note**. Prefer advanced items that strengthen the Node + reachability wedge, not generic enterprise checkboxes.

`[X]` means a slice of that item is already in this tree. It does not mean the advanced bullet shipped, and it does not approve a new version.

### A. Adoption blockers (biggest “why isn’t everyone using this?”)

1. **GitHub App / PR comments**
   - **Today:** `scan --pr-summary` prints Markdown; nothing posts to GitHub/GitLab.
   - **Basic:** GitHub App that comments on PRs with new findings vs baseline (deterministic, no AI).
   - **Advanced:** Check-run annotations per file/line; “Request changes” only on reachable high/critical; bot opens follow-up issues with `fix` patch attached; org-level allowlist of repos; signed webhook + least-privilege install.
   - **Risk:** SPEC historically rejects PR-comment bots as a product category; keep it opt-in, human-approved installs, never auto-merge.

2. [X] **VS Code / Cursor extension** (MCP server is in the tree: `fullshield mcp --stdio`, read-only, `propose_fix` does not write. A VS Code extension was not built.)
   - **Today:** SPEC rejects a VS Code extension; MCP is the intended editor path.
   - **Basic:** Ship a first-class MCP pack + Cursor rules/skills that call `fullshield scan --json` and surface findings in chat.
   - **Advanced:** Language-server-style diagnostics via MCP resources; “apply this fix” that shells to `fullshield fix` with verification; workspace trust prompts; never silently scan `$HOME`.
   - **Risk:** Do not fork into a second product surface that diverges from CLI JSON.

3. [X] **One-click GitHub Action + marketplace** (2.3.0 — Action template + init; Marketplace listing still human)
   - **Today:** `init` can write workflows; marketplace listing/badges are thin.
   - **Basic:** Official Action with pinned digest, `fail-on`, SARIF upload to code scanning, status badge.
   - **Advanced:** Composite Action that runs scan → reachability-ranked summary → optional `fix` dry-run artifact; reusable workflow for monorepos; OIDC-only publish path documented as the trust story.
   - **Risk:** Unsigned marketplace Actions destroy trust; pin by SHA always.

4. **Dashboard SaaS (multi-repo history)**
   - **Today:** Local experimental dashboard only.
   - **Basic:** Hosted read-only history of scan JSON per repo/branch (trends, open vs closed findings).
   - **Advanced:** Org graph of reachable vulns across repos; “blast radius” when a shared lockfile package turns critical; SSO; retention policies; export to SIEM; still no claim of live attack prevention.
   - **Risk:** SaaS is a company product, not a CLI phase; needs privacy, billing, SOC2. Keep scanner useful offline without SaaS.

5. [X] **Signed / attested install for strangers** (2.3.0 — Verify-in-60s + provenance note; no Rekor/sigstore SaaS)
   - **Today:** Provenance on publish; stranger check exists in SPEC release steps.
   - **Basic:** README “verify in 60s” with `npx fullshield@x.y.z --version` + attested package link.
   - **Advanced:** SLSA build provenance on every release; public Rekor/sigstore page; install-guard that refuses non-attested tarballs in CI; weekly rebuild-reproducibility report.
   - **Risk:** Provenance theater without green gates (as with prior 2.1.0 publish timeouts) hurts more than it helps.

6. [X] **Speed as a product claim** (2.3.0 — README cites `bench/perf-v2.json` only; Next.js cold target still unmet)
   - **Today:** 2.2.0 shared AST / parallel modules / lazy taint; PERF2 pool + cache; stored Next.js cold scan still above target.
   - **Basic:** Publish reviewed p50 cold/warm numbers from `bench/perf-v2.json` only after a quiet-machine run.
   - **Advanced:** Public “scan under N seconds on app class X” SLA for CI; incremental `--changed` / diffscan as the default PR path; parse-cache hit-rate metrics in doctor; never invent numbers in docs.
   - **Risk:** Invented benches = credibility death. Accuracy never traded for speed (R26 / FEATURES rules).

7. [X] **Stable recommended defaults** (2.3.0 — `profile` + `init --recommended` + doctor warning)
   - **Today:** Hundreds of `FULLSHIELD_EXPERIMENTAL_*` flags; new users drown.
   - **Basic:** A documented `profile: recommended` (or `fullshield init --recommended`) that enables a small, reviewed set.
   - **Advanced:** Profiles per maturity (`ci-strict`, `pr-fast`, `prod-monitor`); doctor warns when experimental flags are on without a profile; promote flags only with R1 evidence.
   - **Risk:** Promoting noisy experimental rules into default scan is an R10 / CI-break event — needs human approval.

**A — more advanced (extra)**

- A8. [X] **Monorepo workspace orchestration** as a stable product (2.4.0 — multi-workspace lockfile scan by default; single-package unchanged).
- A9. [X] **Policy-as-code pack** for orgs (2.4.0 — `templates/policy/` + load with `profile: recommended` / `ci-strict`).
- A10. [X] **Zero-config first PR**: `init --ci` (2.4.0 — writes Action + config; optional `gh` recipe / injected runner; **no** PR comments per SPEC §31).

---

### B. Parity with Snyk / npm audit / Dependabot (3.1.1)

8. [X] **Auto PRs for dependency bumps (Dependabot-style + reachability)** (3.1.1 / 3.1.2 — `bumps plan` and `bumps open`, nightly template, skips not-imported; does not auto-merge)
   - **Today:** `fix` can propose bumps; no always-on bot.
   - **Basic:** Nightly job opens one PR per reachable high/critical bump, ranked by reachability then severity.
   - **Advanced:** Group transitive bumps by root cause; prefer minimal override vs major bump; attach SBOM diff + VEX draft; reopen only when OSV changes; never edit lockfile by hand — always via package manager in CI.
   - **Risk:** Auto-merge is SPEC-rejected. Human merges only.

9. [X] **License policy** (3.1.1 — direct-dependency allow/deny; not a transitive license graph)
   - **Today:** Limited / experimental license signals.
   - **Basic:** Deny/allow lists on direct deps (e.g. no GPL in production).
   - **Advanced:** Transitive license graph with “introduced by” path; dual-license resolution; SBOM license attestation; CI fail only on production reachability path.
   - **Risk:** License law is not a CVE — keep messaging as policy, not “vulnerability”.

10. [X] **Private registry / org advisory feed** (3.1.1 — registry config plus a local advisory cache; that host is not fetched)
    - **Today:** Public OSV / npm registry paths.
    - **Basic:** Config for private npm registry + offline OSV cache dir.
    - **Advanced:** Org-private advisory JSON ingested like experimental ingest; mirror cache for air-gapped CI; sign org advisories; never phone home without explicit online mode.
    - **Risk:** R15 / network host allowlists — new hosts need SPEC amendment.

11. [X] **EPSS / KEV prioritization** (3.1.1 — a local EPSS file; no EPSS or CISA host)
    - **Today:** Phase 56 blocked (EPSS/CISA hosts) under R15.
    - **Basic:** Only after SPEC allows pinned hosts: enrich findings with EPSS/KEV flags, default scan still works offline without them.
    - **Advanced:** Combine EPSS × reachability × route exposure into a single deterministic priority (you already have experimental priority tables) — publish the formula; no ML black box.
    - **Risk:** Do not ship until hosts are explicitly allowed; offline must stay clean.

12. [X] **Container / base-image scan** (3.1.1 — documented non-goal; a Trivy SARIF file you already have goes to `ingest`)
    - **Today:** SPEC explicitly rejects OS/container as FullShield scope.
    - **Basic / Advanced:** Do **not** build this. Document “pipe Trivy SARIF into `ingest`” instead.
    - **Risk:** Faking container scanning destroys the honesty wedge.

13. [X] **“Ignore forever” UX ↔ GitHub Security Advisories** (3.1.1 — exception file with owner, reason, and expiry; no GitHub alert sync)
    - **Today:** Baseline / suppressions / experimental policy exceptions with expiry.
    - **Basic:** Stable exception file with owner + expiry; CI fails expired exceptions.
    - **Advanced:** Bidirectional sync with GitHub code scanning alerts (dismiss ↔ FullShield exception); require reason codes; audit log of who ignored a reachable critical.
    - **Risk:** “Forever” without expiry is how orgs go blind — default max expiry.

14. [X] **Diff vs last scan as first-class CI gate** (3.1.1 — `init --recommended` writes the diff workflow; `scan --diff` stays experimental)
    - **Today:** Experimental diff / deps-diff.
    - **Basic:** Promote `scan --diff` (or baseline-only new findings) to recommended CI.
    - **Advanced:** Gate on “new reachable” only; moved findings not treated as new; SARIF upload of delta; fail PR if reachable set grows.
    - **Risk:** Promoting experimental → default is R10 if output keys change.

**B — more advanced (extra) (3.1.2)**

- B15. [X] **Reachability-aware Dependabot replacement** (3.1.2 — one plan groups a name and target and skips not-imported rows; it does not replace Dependabot by itself).
- B16. [X] **Malware / install-script sandbox report** (3.1.2 — `preinstall` / `install` / `postinstall` text is reported and never executed).
- B17. [X] **Lockfile provenance gate** (3.1.2 — a local registry-cache entry without `dist.attestations` is not opened; nothing is fetched for that check).
- B18. [X] **Workspace-aware upgrade plans** (3.1.2 — one grouped bump can say it clears N findings; it does not edit the lockfile by hand).

---

### C. Parity with Semgrep / Sonar / CodeQL (3.2.1)

15. [X] **Higher default SAST recall on real apps** (3.2.1 — extra behavior stays behind a flag; default recall was not raised and no recall number is published)
    - **Today:** Strong core sinks; reviewed recall for untouched apps is not published; honesty > hype.
    - **Basic:** Expand sinks/framework packs behind flags; promote only with clean-app + FP bench silence.
    - **Advanced:** Continuous holdout program (Juice Shop, NodeGoat, realworld set) with human-reviewed labels; publish precision/recall only when `reviewed: true`; never weaken ground truth to “win”.
    - **Risk:** Fake recall is an explicit non-goal.

16. **Language packs beyond Node**
    - **Today:** Node/TS backends only.
    - **Basic / Advanced:** Usually a **bad bet** for “#1 npm tool”. If ever: separate package (`fullshield-python`) so the Node CLI stays sharp.
    - **Risk:** Dilutes the wedge; support cost explodes.

17. [X] **Custom rule DSL (stable)** (3.2.1 — local `fullshield.rules.yml` schema 1, literal substrings; no downloaded rule registry)
    - **Today:** Experimental Semgrep-style user rules.
    - **Basic:** Stabilize a small YAML subset (pattern + message + severity) with versioned schema.
    - **Advanced:** Pack registry for org rules (local files only — no downloading third-party registries per SPEC reject); rule tests as fixtures; SARIF taxonomy mapping.
    - **Risk:** Bundling Semgrep registry is SPEC-rejected.

18. [X] **IDE quick-fix** (3.2.1 — `fix --finding` writes one safe fix; MCP `propose_fix` returns a diff and does not write)
    - **Today:** `fix` CLI; experimental fix-verify.
    - **Basic:** MCP/Cursor command: apply safe patch for one finding.
    - **Advanced:** Multi-finding fix groups; verify by re-scan only (no running project tests — R15); rollback snapshot; show diff before write.
    - **Risk:** Auto-running tests is rejected; keep verify = re-scan.

19. [X] **Data-flow UI (taint graphs)** (3.2.1 — an HTML source/sink line when a trace already has both ends; not an interactive graph)
    - **Today:** Trace fields on findings; HTML report exists.
    - **Basic:** HTML report draws source → sink edges for taint findings.
    - **Advanced:** Interactive graph (local only), click node → file:line; export Graphviz/Mermaid for PRs; SARIF code flows filled consistently.
    - **Risk:** Pretty graphs with wrong edges are worse than no graph — gate on determinism tests.

20. [X] **Quality / security grade badges** (3.2.1 — `scan --counts` by severity and reachability; no letter grade)
    - **Today:** No A/B/C score as a product claim.
    - **Basic:** Avoid letter grades; prefer counts by severity × reachability.
    - **Advanced (if forced):** Deterministic score formula published in docs; badge is “reachable critical = 0” not “Grade A”; never market as certification.
    - **Risk:** Marketing scores invite gaming and distrust.

**C — more advanced (extra) (3.2.2)**

- C21. **Framework-deep packs as products**: Next App Router, Nest DI, tRPC, Prisma — each with FP-negative fixtures and promotion criteria.
- C22. **Cross-file summary caching** as default with byte-identical findings (extend 2.2.0 speed work into accuracy-preserving summaries).
- C23. [X] **Second-order / stored XSS and SSRF** (3.2.2 — same-file `req.body` later passed to `res.send` or `res.end` only; not cross-file SSRF).
- C24. [X] **Authz/IDOR** (3.2.2 — `req.params.id` is not an IDOR finding and does not fail the default high gate; `SAST-IDOR-001` stays experimental and its source does not fail CI).

---

### D. Parity with runtime / WAF / RASP vendors (3.3.1)

21. [X] **Safe-by-default block mode** (3.3.1 — with the guard flag on, block applies to SQL and shell only; other sinks stay monitor)
    - **Today:** Prefer `monitor`; experimental RASP is fail-open; no prevention claim.
    - **Basic:** Documented shadow mode → monitor → optional block for a tiny allowlisted sink set.
    - **Advanced:** Per-route policy; dry-run counters in production for N days; block only on high-confidence sinks with escape hatch header for break-glass; chaos tests for fail-open.
    - **Risk:** Claiming “prevents attacks” is marketing reject. Stay monitor-first.

22. [X] **Attack dashboards + alerting** (3.3.1 — a local `webhookJson` body, at most 5 per 60 seconds, not posted; no timeline and no PagerDuty)
    - **Today:** Slack/webhook notify on scan; runtime logs locally.
    - **Basic:** Structured runtime events to webhook (JSON) with rate limits.
    - **Advanced:** Local or SaaS timeline of blocked/monitored events; correlate to last scan finding IDs; PagerDuty; still not a SIEM replacement.
    - **Risk:** Multi-tenant cloud is company infra, not scanner honesty.

23. [X] **eBPF / network layer** (3.3.1 — documented non-goal; external alerts stay on `ingest`)
    - **Today / forever for FullShield:** Out of product honesty — don’t chase.
    - **Alternative:** Integrate by ingesting external alerts; never pretend FullShield is CrowdStrike.

**D — more advanced (extra) (3.3.2)**

- D24. **Runtime ↔ scan closed loop**: runtime sees SQLi-like payload → emit fingerprint → next CI scan highlights matching sinks.
- D25. [X] **Canary / confirm** (3.3.2 — an `unconfirmed` row is not a pass while the guard flag is on; not a scheduled job).
- D26. [X] **Response size cap** (3.3.2 — a sample over 4096 bytes sets `overCap`; this is not a DLP product, and the older experimental DLP flag is unchanged).
- D27. [X] **Mode enum** (3.3.2 — `block-experimental` is the block name while the guard flag is on; no per-framework middleware pack).

---

### E. Trust & distribution (what makes tools “#1” in practice) (3.4.1)

24. **Case studies + public benchmarks**
    - **Today:** Internal benches; comparison docs exist carefully; no fake “#1” claims.
    - **Basic:** Side-by-side on NodeGoat / Juice Shop / a real OSS API vs `npm audit` + Semgrep (same commit SHAs).
    - **Advanced:** Quarterly public scorecard: reachable vulns found, FP samples reviewed, cold-scan time; methodology frozen before the run (eval-plan style).
    - **Risk:** Cherry-picked wins destroy trust. Pre-register metrics.

25. [X] **SOC2 / company security page** (3.4.1 — `docs/security-page.md` says a cloud-free scan sends no customer scan data; no SOC2 claim)
    - **Today:** SECURITY.md for the package; company assurance is separate.
    - **Basic:** Public security page: how FullShield handles customer scan data (ideally: none in cloud-free mode).
    - **Advanced:** SOC2 if SaaS exists; pen-test summary; vulnerability disclosure SLAs; employee access controls — for the *company*, not claimed as scanner features.
    - **Risk:** Don’t block open-source CLI progress on SOC2 theater.

26. [X] **Weekly “CVEs that matter for Node” digest** (3.4.1 — `digest --file` prints npm ids from a local JSON array and does not fetch; not a weekly Express-reachability digest)
    - **Today:** No productized digest.
    - **Basic:** Blog/script: new OSV npm CVEs filtered by “would be reachable in a typical Express app”.
    - **Advanced:** Personalized digest from org SBOM + last FullShield reachability classes; email/RSS; unsubscribe; never require SaaS for core scan.
    - **Risk:** Becoming a media company dilutes engineering — automate from the engine.

27. [X] **Template configs per stack** (3.4.1 — `init --stack` writes a monitor note for express, nest, next, fastify, or hono and does not suppress a finding)
    - **Today:** Generic `init`.
    - **Basic:** Templates: Express API, Nest, Next App Router, Fastify, Hono.
    - **Advanced:** Template includes CI workflow, recommended profile, runtime middleware snippet, and a “first week” ignore baseline for known framework noise — with expiry.
    - **Risk:** Templates that hide real vulns are worse than no template.

28. [X] **Trainer / interactive tour** (3.4.1 — `init --tour` prints five steps and writes nothing; no planted tutorial app)
    - **Today:** Demo docs; stranger check on release.
    - **Basic:** `fullshield init --tour` walks scan → fix dry-run → CI in 5 minutes.
    - **Advanced:** Local tutorial app with planted vulns; progress checklist; links each finding to `rules/<ID>.md`; graduate into real repo scan.
    - **Risk:** Keep tutorial fixtures out of the published pack if they look like real secrets (concatenation rule).

**E — more advanced (extra) (3.4.2)**

- E29. **Ambassador / OSS design partners**: 10 Node companies with public quotes after 30 days of CI use.
- E30. **Reproducible stranger pack**: GitHub Action that runs the SPEC stranger check on every tag and posts a green/red status to the release.
- E31. **Compatibility matrix**: Node 22/24 × npm/pnpm/yarn/bun lockfiles × Express/Fastify/Nest/Next — published and CI-gated.
- E32. [X] **“FullShield vs npm audit” one-pager** (3.4.2 — `docs/vs-npm-audit.md` describes reachability and states no finding count).

### F. Scanners already in the tree and missing from A–E

These are in the product today, mostly behind `FULLSHIELD_EXPERIMENTAL_*`. `[X]` means the check exists. It does not mean the check is on for a default scan.

- F1. [X] **Core SAST** — injection, XSS, SSRF, path, and command sinks on the default scan.
- F2. [X] **Secrets** — default scan, plus experimental git history, client-bundle keys, and a read-only live check that does not log the key.
- F3. [X] **Config** — headers, CORS, and trust-proxy on the default scan; reflected CORS stays experimental.
- F4. [X] **Supply chain** — malicious OSV, typosquat, lock hygiene, provenance, release cooldown, version inflation, and install-implant file names.
- F5. [X] **Capability profile** — static process, network, fs, env, eval, native, dynamic require, install scripts, and obfuscation. It does not run package scripts.
- F6. [X] **Extra sinks** — LDAP, CRLF, mail headers, CSV formula, browser automation, dynamic `import()`, Redis `eval`, XPath, search-query strings, object-store keys, and worker paths.
- F7. [X] **Extra classes** — crypto misuse, Electron `webPreferences`, vendored JS banners, SSTI, missing webhook verifiers, session fixation, log leaks, Next.js boundary, DOM XSS, TLS verification off, and credential files.
- F8. [X] **Noisy classes behind one flag** — ReDoS, deserialization, XXE, upload, cookies, CSRF, mass assignment, timing compare, hash cost, GraphQL, and trust-proxy.
- F9. [X] **Framework sources** — Next.js, Nest, Hono, and Koa taint sources behind one flag. Default scan is unchanged.
- F10. [X] **MCP config** — client config rules and poison, exfil, and duplicate-tool checks. Scanning `$HOME` is a separate opt-in.
- F11. [X] **Agent files** — instruction-file injection and a spawn of `claude`, `codex`, or `gemini` with a bypass flag.
- F12. [X] **Light IaC** — GitHub Actions, Terraform, Kubernetes, and compose. Not a full IaC product.
- F13. [X] **OpenSSH exposure report** — Linux only. It does not block, patch, or harden sshd.
- F14. [X] **VEX** — `not_affected` only when reachability is `not-imported`. Otherwise `under_investigation`.
- F15. [X] **SBOM** — CycloneDX, plus experimental SPDX. Licenses are copied from package data.
- F16. [X] **npm audit file diff** — compares a local `npm audit --json` with scan findings and does not run npm.
- F17. [X] **Lockfile diff** — a git ref versus the working tree.
- F18. [X] **Edge posture** — headers and a couple of exposure paths on a URL you pass. No crawl and no payloads.
- F19. [X] **Schedule** — an OS timer every 2 hours, 60 local reports.
- F20. [X] **Watch** — alerts only when a new OSV hit appears versus the last scan.
- F21. [X] **Inline ignore** — `fullshield-ignore` requires a reason.
- F22. [X] **Fix verify** — a patch is re-scanned in memory. A patch that introduces a finding is not written.
- F23. [X] **Doctor** — Node, lockfile, cache, flags, config parse, and whether OSV may use the network.
- F24. [X] **Explain** — one finding from a scan file. Never a verdict.
- F25. [X] **Compliance mapping** — evidence-style text. Not a certification.
- F26. [X] **Local dashboard** — `127.0.0.1` only.
- F27. [X] **Threat model** — STRIDE plus Mermaid.
- F28. [X] **Honeytokens** — decoy routes stay low; a canary credential is the critical event.
- F29. [X] **Phantom and lock mismatch** — experimental dependency hygiene, not a default finding.
- F30. [X] **RSC pin** — a lockfile on a named vulnerable `react-server-dom-*` version.
- F31. [X] **Vite `server.fs`** — `strict: false` or an allow of `/`.
- F32. [X] **Host header into a redirect or mail** — experimental.
- F33. [X] **Markdown HTML** — `markdown-it` with `html: true`, or `marked`, fed request data.
- F34. [X] **Auth.js `trustHost: true`** — experimental.
- F35. [X] **Unfixed abandoned deps** — no fixed version and last publish older than 730 days. Experimental.
- F36. [X] **Low-confidence IDOR hint** — experimental, and that source does not fail CI.

### G. Advanced scanners not built

No `[X]`. Nothing here is a default scan, a flag, or an approved version.

- G1. **Cross-file stored XSS and stored SSRF** — a value saved in one file and used in another. C23 is same-file only.
- G2. **Cross-file summary cache** — byte-identical findings, on by default. C22 was not built.
- G3. **Next.js App Router and server actions** — a pack with false-positive fixtures and a promotion rule. The Next boundary flag is not that pack.
- G4. **Nest guards** — a route with no guard, and a guard that does not check the object id.
- G5. **tRPC procedures** — a `publicProcedure` that reads an id and writes a row with no ownership check.
- G6. **Prisma unsafe raw SQL** — a string passed to `$queryRawUnsafe` or `$executeRawUnsafe`. A tagged `$queryRaw` stays clean.
- G7. **Promote the noisy class flag** — ReDoS, XXE, deserialization, CSRF, cookies, mass assignment, and GraphQL move one at a time, only after clean-app stays quiet.
- G8. **OpenAPI drift** — paths in a local OpenAPI file that have no matching route, and routes that have no path in the file.
- G9. **gRPC and protobuf** — a service method that passes a request field into SQL, shell, or a URL.
- G10. **WebSocket messages** — a `message` event used as a taint source.
- G11. **Queue payloads** — Bull, Bee, or an SQS handler that treats the job body as code or a path.
- G12. **Request smuggling and cache poisoning** — ambiguous `Content-Length` / `Transfer-Encoding`, and a cache key that includes a request header.
- G13. **Second-order SQL** — a value written in one request and concatenated into SQL in another file.
- G14. **IDOR that can be promoted** — a high-confidence object-id check. The current hint must stay off the default fail gate.
- G15. **Missing auth on a state-changing route** — a heuristic with a published false-positive budget, not a default high finding.
- G16. **Zip slip** — an archive entry whose path escapes the destination directory.
- G17. **Unsafe YAML load** — `js-yaml` `load` of request data with a schema that allows functions.
- G18. **OAuth `redirect_uri`** — a redirect target taken from the query string with no allowlist.
- G19. **App-level prompt injection** — user text copied into a system prompt or a tool argument. Agent-file rules do not cover this.
- G20. **MCP tool the app exposes** — a tool schema whose description tells the model to ignore instructions or run a shell.
- G21. **GitHub Actions token risk** — `pull_request_target` with a checkout of the PR head, or a third-party action on a mutable tag with a write token. Light IaC is not this check.
- G22. **Dockerfile root and privileged Kubernetes** — `USER` missing or root, `privileged: true`, `hostPath`, `hostNetwork`. Not a container CVE scanner.
- G23. **SBOM versus `node_modules`** — a package present on disk and absent from the SBOM, or the reverse.
- G24. **Changed-workspace CI** — in a monorepo, scan only workspaces touched by the diff, with the same finding keys.
- G25. **User-rule tests** — `fullshield.rules.yml` fixtures that must pass before the rule is loaded.
- G26. **Pre-commit time budget** — scan changed files only, and refuse to scan `$HOME`.
- G27. **GitLab and Bitbucket output** — the same JSON findings, no second scanner.
- G28. **Fix rollback** — one snapshot taken before a safe fix, restored if the re-scan is worse.
- G29. **Multi-finding fix** — a group of safe fixes, still without running the project tests.
- G30. **Literal dynamic import reachability** — `import("./" + name)` is not treated as a static import; a fully literal `import("pkg")` can be.
- G31. **Function reachability without OSV `affected_functions`** — do not invent a symbol list. Stay at import level until the advisory names a function.
- G32. **Taint graph export** — Graphviz or Mermaid for one finding, only from steps the trace already has.
- G33. **Runtime fingerprint on the next scan** — a SQL fingerprint stored by the guard flag highlights a matching sink. D24 does not do this yet.
- G34. **Scheduled confirm** — a localhost canary on a timer, with `unconfirmed` still not a pass.
- G35. **Weekly reachable digest** — local OSV npm ids that an Express import would reach. `digest --file` does not do that filter.
- G36. **pnpm, yarn, and bun as claimed CI cells** — only after a real job runs them. The compatibility page marks them not claimed.
- G37. **Express, Fastify, Nest, and Next as claimed CI cells** — same rule. Not claimed today.
- G38. **Stranger-check workflow** — a workflow that runs the stranger steps on a tag. The template is not that workflow.
- G39. **Tutorial app** — planted bugs, a checklist, and a link from each finding to its rule note. Keep planted secrets out of the published pack.
- G40. **Internal package name on the public registry** — a scope you list locally also resolves from `registry.npmjs.org`.
- G41. **Dependency confusion allowlist** — the internal scope list is a file in the repo, not a network call.
- G42. **Exception audit** — who added a reachable critical exception, when, and when it expires. No GitHub sync.
- G43. **SARIF delta** — upload only findings that are new versus the baseline.
- G44. **Cloud metadata SSRF** — a user-controlled URL whose host is the metadata address, including a decimal or IPv6 form.
- G45. **DNS rebinding** — document the limit. A static scanner cannot see a DNS answer that changes.
- G46. **Service-worker and cache deception** — a cacheable response that reflects a credentialed request.
- G47. **Password-reset token in a URL** — the token is written into a redirect or an email link that is also logged.
- G48. **Account enumeration** — a login and a reset that use different messages for a missing user. High false-positive risk; stay experimental.
- G49. **Rate limit missing on login** — a heuristic only, never a default high finding.
- G50. **OIDC in GitHub Actions** — `id-token: write` on a workflow that also checks out an untrusted ref.
- G51. **Do not build** — container and OS package scanning, eBPF, a second language inside this package, a letter grade, a recall number, a company quote, or a claim that the process prevents attacks.

### H. Further features not built

No `[X]`. Nothing here is a default scan, a flag, or an approved version. These are not the same items as A–G.

**Package and lockfile**

- H1. **Trojan source** — bidirectional and invisible characters in a package name, a lockfile URL, or a JavaScript string.
- H2. **Homoglyph names** — a package name that looks like another using mixed scripts, beyond edit-distance typosquat.
- H3. **Floating git dependencies** — a `git` or GitHub dependency on a branch or tag, not a commit.
- H4. **Paths outside the repo** — a `file:` or `link:` dependency whose target leaves the project root.
- H5. **Two lockfiles disagree** — `package-lock.json` and `yarn.lock` or `pnpm-lock.yaml` resolve the same name to different versions.
- H6. **Override pins a vulnerable version** — `overrides`, `resolutions`, or `pnpm.overrides` forces a version the local OSV cache already marks.
- H7. **patch-package reintroduces a sink** — a file under `patches/` puts a request value back into SQL, shell, or HTML.
- H8. **Publish would leak files** — `files` or `.npmignore` would pack `.env`, a private key, or `.github`.
- H9. **Workspace meant to stay private** — `private` is missing or false on a workspace package.
- H10. **Install script downloads a URL** — the script text contains `curl` or `wget`. The script is not executed.
- H11. **Binary download with no hash** — a script or config fetches a binary and has no integrity pin.
- H12. **`--require` or `NODE_OPTIONS` in a script** — a start or install script injects a loader.
- H13. **Node version drift** — `engines`, `.nvmrc` or `.node-version`, and the CI node version are not the same.
- H14. **DevDependency imported by production code** — a production file imports a dependency declared only under `devDependencies`.
- H15. **`@types` major skew** — the `@types` package major does not match the runtime package in the lockfile.

**Frameworks and sinks**

- H16. **Knex, Sequelize, and TypeORM raw queries** — request data passed to `.raw`, `sequelize.query`, or `createQueryBuilder` string SQL.
- H17. **Mongo query injection** — request data in `$where`, a query object, or a mongoose `where`.
- H18. **WebSocket and Socket.IO** — a `message` or `connection` payload used as a taint source.
- H19. **Next.js URL features** — `images.remotePatterns` left open, or a rewrite/redirect to a user-controlled URL.
- H20. **Next.js middleware and server actions** — a matcher of `/:path*`, or a server action with no origin check in the same file.
- H21. **Other Node frameworks** — React Router, Remix, SvelteKit, and Astro server endpoints as taint sources. Still this package, still Node.
- H22. **Fastify body with no schema** — a route with no body schema whose body reaches a sink.
- H23. **GraphQL production defaults** — introspection enabled, or no depth limit, in a file that is not a test. Separate from the noisy classes flag.
- H24. **Missing security headers middleware** — an Express or Fastify app listen with no helmet or header setup in the app file.
- H25. **Stack traces to the client** — an error handler sends `err.stack` in the response outside tests.
- H26. **Huge body parser** — `express.json` or the Fastify body limit is missing or above a limit written in the rule note.
- H27. **Debug surfaces in source** — Swagger, GraphQL Playground, or a `/metrics` route registered with no auth check in that file.

**Auth and cloud APIs**

- H28. **OAuth `state` and PKCE** — an authorize redirect built without `state`, or a token exchange without a verifier.
- H29. **Post-login redirect** — the next URL after login comes from the query string and is not allowlisted.
- H30. **Literal session or JWT secret** — `secret:` or `jwt.sign` uses a string literal.
- H31. **`SameSite=None` without `Secure`** — a cookie setter does that outside tests.
- H32. **Password hashed with MD5 or SHA1** — `createHash` of a password field. Bcrypt cost stays on the classes flag.
- H33. **Email or password change** — the handler updates the account and does not read the current password or session in that file.
- H34. **Presign with no expiry** — an S3 presign call has no `expiresIn` or `Expires`.
- H35. **Public object ACL** — source sets `public-read` or `public-read-write`.

**CI, Docker text, and repo hygiene**

- H36. **Actions expression injection** — `${{ github.event.* }}` interpolated into a `run:` script.
- H37. **Unpinned third-party action** — a `uses:` that is not this repo and not a commit SHA.
- H38. **Secret passed into a third-party action** — `env:` or `with:` sends a secret to an action outside the repo.
- H39. **Checkout credentials on an untrusted ref** — `persist-credentials: true` together with a pull request head.
- H40. **Write permissions on `pull_request`** — a workflow triggered by `pull_request` sets `contents: write` or `id-token: write`.
- H41. **Ignore files** — `.gitignore` or `.dockerignore` exists and does not mention `.env`.
- H42. **Secret in an image build** — a Dockerfile `ARG`, `ENV`, or `COPY` names `.env`, `id_rsa`, or `.npmrc`. This is text in the Dockerfile, not an image scan.
- H43. **Compose default passwords** — a service publishes a port and sets `PASSWORD` to a literal.
- H44. **Publish workflow** — `npm publish` in a workflow with a node auth token in the file, and no OIDC `id-token` permission.

**Output, policy, and CI shape**

- H45. **Reviewdog and GitLab SAST** — those formats from the same findings. No second scanner.
- H46. **JSON Schema** — published schemas for scan JSON, policy, and `fullshield.config.json`.
- H47. **`doctor --json`** — includes how old the local OSV cache is, and a non-zero exit when that age is past a number in the config.
- H48. **Relative paths only** — SARIF and JSON can omit machine-specific prefixes so two checkouts match.
- H49. **Masked secrets in reports** — HTML, SARIF, and logs do not print a secret value the secrets module already matched.
- H50. **Report file mode** — new report files are created so only the current user can read them.
- H51. **Lockfile-only job** — a command that scores dependencies and does not parse application JavaScript.
- H52. **CODEOWNERS note** — a finding can include the owner pattern for that path. It does not request a review.
- H53. **Policy simulation** — print which findings would fail the policy, and write nothing.
- H54. **Published priority formula** — severity, reachability, and a number from a local EPSS file. No new host and no learned model.
- H55. **Smallest bump first** — the plan prefers an override or a patch over a major, and says when it did that.
- H56. **Bump delta** — between the installed version and the target, report new install-script text, a license field change, and a new native addon. Do not run the scripts.
- H57. **Air-gap doctor** — with `--offline`, exit non-zero when a required local cache file is missing. Do not fetch it.
- H58. **Self-scan** — this repo’s CI runs FullShield on itself with the same default-scan rules as any other app.
- H59. **Generated file mapping** — a finding under `dist/` or a generated client names the source map or schema line when that file exists.
- H60. **Still out** — no telemetry, no phone-home, no second language in this package, no container CVE database, and no claim that a process prevents an attack.

## What I would not add to chase “#1”

- Full container/OS scanning
- Claiming “prevents attacks” / WAF replacement
- Fake recall numbers
- Becoming a general multi-language Sonar clone

## Short strategy (if the goal is market share)

1. Own one sentence: “The only Node scanner that ranks lockfile CVEs by real reachability and ships fix + runtime in one install.”
2. Close A1–A7 before cloning Snyk’s long tail.
3. Ship B8 (auto bump PRs ranked by reachability) — that’s a Dependabot killer for Node teams.
4. Publish speed + accuracy from real runs only.

## Lanes (pick one before a version plan)

Still list-only until a named version’s inventory at the top of this file is approved:

1. **Adoption** — Action + PR comments + init path
2. **Dependabot killer** — reachability-ranked auto-bump PRs
3. **Accuracy / speed** — become the scanner people trust on real Node apps
4. **All of the above** as a multi-version roadmap (rank, not build everything at once)
