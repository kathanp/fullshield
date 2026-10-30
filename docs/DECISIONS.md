# Decisions

## ESLint disables

Phase 94 recorded 0 `eslint-disable` comments in `src/`. A new one needs `-- reason` on the same line and a row in this file naming the path.

## Autopilot decisions

D-1 | phase-501 | Diff scan uses one import hop, `FS-E018`, and the existing rule ids for a request value returned from a changed file | The features file limits the frontier to the changed file, its relative-literal importers, and its relative-literal imports. Hop 2 would read more of the repo than that file allows. `FS-E018` is the next CLI code. It is matched before `FS-E006` because the flag name contains that prefix. | APPROVED

D-2 | phase-502 | A stored field and a closed-over name each cross one boundary | The features file's examples are `obj.a` and one nested function. Depth 2 stays silent so the negative fixture is the closest miss. `JSON.parse` stays tainted because it is not a sanitizer. | APPROVED

D-3 | phase-503 | Field and closure taint is the default scan | The approved features file promotes phase 502. The flag stays accepted and does not turn the behavior off. On 2026-10-24 the human delegated the R3 edit of the two unset-flag assertions in `phase502-flow2.test.ts`. | APPROVED

D-4 | phase-504 | ORM raw queries and the named shell variants are the default scan | The approved features file promotes those phase 27 sinks. The flag stays accepted and does not turn them off. The same delegated R3 edit covers the two flag-off assertions in `coverage-gaps.test.ts`. Bindings and `execFile` stay silent. | APPROVED

D-5 | phase-505 | LDAP findings require an ldap import or an ldap receiver | A bare `bind` of request data is common and would light up `clean-app`. The import specifier or the receiver identifier must contain `ldap`. CWE-90. | APPROVED

D-6 | phase-506 | Reflected CORS is the request Origin header plus credentials on that response | A fixed origin, including `clean-app`'s allow-list, stays silent. `origin: '*'` stays `CONFIG-CORS-001`. CWE-942. | APPROVED

D-7 | phase-507 | SQLite `exec` and `prepare` join `SAST-SQLI-001` only when the file names sqlite | A global `exec` sink would also flag `child_process`. The query text has to be tainted, so a literal `?` placeholder stays silent. R10 approved. | APPROVED

D-8 | phase-508 | Bun and Deno command sinks stay on the existing command rule | `Bun.spawn` reports a tainted argument without `shell: true`, as the features file says. A `$` template requires a `bun` import so a zx template stays on the existing `$.raw` check. R10 approved. | APPROVED

D-9 | phase-509 | `evaluate` fires only for mathjs, expr-eval, and vm2 bindings | A bare `evaluate()` in the same file as an unrelated import stays silent. `new VM` reports only a non-literal `code` or `eval` option. R10 approved. | APPROVED

D-10 | phase-510 | RSC findings are the four exact React versions from the 2025-12-03 advisory | `19.0.0-canary` is not one of those four. The check reads lockfile text and does not call the registry. CWE-502. | APPROVED

D-11 | phase-511 | A release-age gate is three days, in the unit that package manager uses | npm is days, pnpm is minutes, yarn is a duration, bun is seconds. A project with no package-manager config file stays silent so `clean-app` stays at 0. CWE-829. | APPROVED

D-12 | phase-512 | Worm files are `setup_bun.js` and `bun_environment.js`, capped at 2000 package manifests | The default walk skips `node_modules`, so this check reads that directory itself and does not follow symlinks or the npm cache. CWE-506. | APPROVED

D-13 | phase-513 | An inflated version has major 9999 or greater, or patch 999 or 9999 | `1.2.3` stays silent. A prerelease suffix is not this shape. CWE-427. | APPROVED

D-14 | phase-514 | Agent instruction files are the named paths only | Unicode Tag, zero-width, bidi, the two phrases, a secret word next to an http URL, and the three bypass flags. Other markdown stays unread by this check. | APPROVED

D-15 | phase-515 | A coding-agent bypass is the program and the flag in the same call | `claude` without the flag stays silent. The scanner does not spawn it. CWE-78. | APPROVED

D-16 | phase-516 | MCP poison reads `mcpServers` JSON and does not connect | Elicitation, a shell-like or injection default, and a tool name shared by two servers. `MCP-001` through `MCP-005` stay on their own flag. | APPROVED

D-17 | phase-517 | Vite reports `server.fs.strict: false` and a root allow entry | A config that omits `server.fs` stays silent. CWE-22. | APPROVED

D-18 | phase-518 | Host-header links are `Host` and `X-Forwarded-Host` inside an absolute URL at a redirect or mail sink | `req.hostname` and a fixed host stay silent. CWE-644. | APPROVED

D-19 | phase-519 | Markdown HTML requires the library import and request data | `html: true` plus a literal `render` stays silent. `marked` of a literal stays silent. CWE-79. | APPROVED

D-20 | phase-520 | `trustHost: true` requires an Auth.js or NextAuth mention | `false` and an omitted property stay silent. CWE-346. | APPROVED

D-21 | phase-521 | A SQL tagged template is the tag `sql` plus one of the five driver imports | A bare tag, or a template with no interpolation, stays silent. The bound-argument `query` in `clean-app` stays silent. R10 approved. | APPROVED

D-22 | phase-522 | `execFile` fires only when the command path is request data | A literal path with a tainted later argument stays silent, which is `clean-app`'s `ping`. `shell: true` is not required. R10 approved. | APPROVED

D-23 | phase-523 | `end` is an XSS sink only when the body contains HTML | `send` and `write` stay on the existing rule. `res.status(401).end()` has no argument and stays silent. | APPROVED

D-24 | phase-524 | SSRF options are `hostname`, `host`, `href`, or `path` on `http.request` or `https.request` | A literal hostname stays silent. A call the existing rule already reports is not reported again. | APPROVED

D-25 | phase-525 | `Bun.file` is always a path sink; `glob` and `opendir` require `fs` | A literal path stays silent. Existing `readFile` and `sendFile` stay on the existing rule. | APPROVED

D-26 | phase-526 | `location` joins the redirect rule | `redirect` stays on the existing rule. A literal `/home` or `/` stays silent. | APPROVED

D-27 | phase-527 | Deep JWT is an empty algorithm list or a non-literal list | A missing `algorithms` option is already a stable finding and is not reported twice. `['HS256']` stays silent. | APPROVED

D-28 | phase-528 | `assign` joins the prototype rule; `merge` does not | `clean-app` defines `merge`, not `assign`. A `__proto__` comparison in the file stays silent. | APPROVED

D-29 | phase-529 | An unparsed lockfile is an empty graph, not a thrown error | `JSON.parse` of `package-lock.json` already returns an empty graph. Yarn and pnpm parsers do not throw on `{`. The scan-level test locks that, including a workspace lockfile. No new finding, so default scan output does not change. | APPROVED

D-30 | phase-530 | The test toolchain moves to vitest 5.0.5 or the phase is parked | `npm audit` names 5.0.5 as the fix for vitest, coverage, mocker, vite, esbuild, and tinypool. Those packages are devDependencies and are not packed. An existing test is not edited to make the bump pass. | APPROVED

D-31 | phase-531 | body-parser is updated inside the ranges express and the MCP SDK already allow | GHSA-27r3-jxmh-p828. `express@^4.22.3` allows `body-parser@1.20.9`. The MCP SDK devDependency stays inside optional peer `^1.32.1`. No `overrides` entry, so installing fullshield does not force a consumer's body-parser. | APPROVED

D-32 | phase-532 | Header injection is the header value, not the status or the header name | CWE-113. A tainted status, or a tainted header name with a literal value, stays silent. `writeHead(200)` stays silent. | APPROVED

D-33 | phase-533 | Mail findings require one of the three imports and a named field | A bare `send` of request data is `res.send`. The field has to be `to`, `cc`, `bcc`, `subject`, `from`, `replyTo`, `html`, or `text`. CWE-93. | APPROVED

D-34 | phase-534 | A `.csv` `writeFile` fires without a csv import; other writers require the import | `writeFile('notes.txt', req.body)` is not a spreadsheet. `write(req.body)` without `csv-stringify`, `fast-csv`, `json2csv`, or `csv` stays silent. CWE-1236. | APPROVED

D-35 | phase-535 | Browser automation uses the existing `FULLSHIELD_EXPERIMENTAL_BROWSER` flag | The features file names that flag. It is already phase 101. Phase 101 rules stay. `goto` and `pdf` are CWE-918. `setContent` is CWE-79. `vulnerable-app` has none of these imports, so the existing flag-on comparison stays equal. | APPROVED

D-36 | phase-536 | Dynamic import fires only when the specifier is request data | A literal specifier and a binding of a literal stay silent. CWE-829. The scanner does not load the module. | APPROVED

D-37 | phase-537 | `set` is a header sink only on a response receiver | `cache.set`, `map.set`, and `session.set` are not HTTP headers. `setHeader`, `append`, `header`, and `writeHead` stay as phase 532. CWE-113. | APPROVED

D-38 | phase-538 | `send` is a mail sink only on a mail receiver | `res.send` of an object is an HTTP body. `sendMail` stays as phase 533. The receiver is `mail`, `transporter`, `transport`, `sg`, `mg`, or a name that contains `mail`. CWE-93. | APPROVED

D-39 | phase-539 | `write` and `format` are not CSV sinks on a response receiver | `res.write` is an HTTP body. `stringify`, `writeToPath`, and a `.csv` `writeFile` stay as phase 534. CWE-1236. | APPROVED

D-40 | phase-540 | Redis `eval` / `call` / `sendCommand` with request data | Ordinary `get`/`set` of a key are not script sinks. CWE-94. The scanner does not talk to Redis. | APPROVED

D-41 | phase-541 | XPath `select` / `evaluate` with request data | Only when `xpath`, `xpath.js`, or `libxmljs` is imported. CWE-643. | APPROVED

D-42 | phase-542 | Search `q` or `query.query_string.query` from request data | `index`/`get`/`ping` stay silent. CWE-943. | APPROVED

D-43 | phase-543 | Object-storage `Key` or `Prefix` from request data | `Bucket` alone is not enough. CWE-22. | APPROVED

D-44 | phase-544 | `Worker` path or `workerData` from request data | Requires a `worker_threads` import. CWE-94. | APPROVED

D-45 | phase-545 | Shared AST is on by default | Phase 78 proved parse-once is finding-identical. File skip stays PERF2-only. | APPROVED

D-46 | phase-546 | Module parallelism is on by default | Deterministic merge by module name then finding id. Finding keys stay identical. | APPROVED

D-47 | phase-547 | Lazy taint is on by default | Phase 78 proved byte-identical on fixtures and bench apps. | APPROVED

D-48 | phase-548 | PERF2 enables the worker parse pool | `FULLSHIELD_PARSE_WORKERS` caps pool size. Pool errors fall back in-process. | APPROVED

D-49 | phase-549 | PERF2 may reuse a local parse cache | Keyed by content hash and version. Corrupt entries are discarded. No network. | APPROVED


D-50 | phase-550 | Ship templates/action/ as Phase 59 named; no PR comments | Action pins fullshield version, uploads SARIF, optional baseline cache. Marketplace listing stays human (R1). | APPROVED
D-51 | phase-551 | Verify-in-60s docs only; no install phone-home | README names 2.3.0, npm page, GitHub tag, OIDC provenance. No new hosts. | APPROVED
D-52 | phase-552 | Speed claims only from bench/perf-v2.json | measured:true + label. Unmet Next.js target stated; no invented timings. | APPROVED
D-53 | phase-553 | profile enum recommended|ci-strict|pr-fast|prod-monitor | Bundles existing defaults only. init --recommended writes profile. Doctor warns on many experimental flags without profile. No R10. | APPROVED

D-54 | phase-554 | Workspace lockfile scan on by default for multi-workspace trees | Single-package identical to 2.3.0. R10 only for multi-workspace attribution. Flag remains accepted. | APPROVED
D-55 | phase-555 | Policy pack under templates/policy; on for profile recommended|ci-strict | No profile → policy off unless experimental flag. No new SAST ids. | APPROVED
D-56 | phase-556 | init --ci writes CI files; optional gh PR; local summary only | Never posts PR comments (SPEC §31). --no-pr skips gh. | APPROVED

D-57 | phase-554 | R3 edit of phase54 flag-off assertion | Approved FEATURES 2.4.0 A8 promotes workspace scan to default; the old flag-off silence assertion is replaced. | APPROVED

D-58 | phase-557 | Bump PRs keep reachable high and critical only, one gh pr create each, never merge | The features file ranks by reachability then severity and refuses auto-merge. Not-imported rows are omitted. FS-E020. | APPROVED
D-59 | phase-558 | License policy matches the whole license string, case-insensitive | Allow wins over the same deny string. A missing license stays silent. The message says policy, not vulnerability. Medium, CWE-1104. | APPROVED
D-60 | phase-559 | Private registry is config plus a local org-advisories cache | https without userinfo. The host is not allowlisted and is never fetched. 1000000 byte cap. EPSS and CISA hosts stay blocked. | APPROVED
D-61 | phase-560 | EPSS and KEV come from a local file | Scores outside 0..1 are rejected. epssPriority uses the published formula. No new finding and no network. | APPROVED
D-62 | phase-561 | Container and OS scanning is a documented non-goal | Trivy SARIF goes to existing ingest. No new rule and no new host. | APPROVED
D-63 | phase-562 | Exceptions need owner, reason, and expiry within 365 days | Expired rows fail CI and do not suppress. No forever value. FS-E022. | APPROVED
D-64 | phase-563 | init --recommended writes the diff workflow | scan --diff stays behind FULLSHIELD_EXPERIMENTAL_DIFFSCAN. Plain init does not write the file. No PR comments. | APPROVED
D-65 | phase-564 | Bump plan groups one name and target, reports install scripts, and can block missing provenance | No new flag or command. Scripts are read and never executed. Provenance block uses the existing provenance flag and the local registry cache only. Not-imported rows stay unopened and are counted. | APPROVED
D-66 | phase-565 | Local YAML rules, severity counts, one safe fix, and HTML taint edges | One new flag. Patterns are literal substrings and are never fetched. Counts are not a grade. A one-finding fix does not run project tests. An edge is drawn only when the trace already has both ends. | APPROVED
D-67 | phase-566 | Same-file stored response stays on the parity flag | No new flag or command. Encoded output, framework helpers, and req.params.id are not findings. Default high CI does not fail on this medium finding. | APPROVED
D-68 | phase-567 | Block mode stays monitor-first and webhook JSON is local | New flag narrows block to sql and shell. Other sinks stay monitor. At most 5 webhook bodies per 60 seconds, not posted, no sample. No eBPF and no new host. | APPROVED
D-69 | phase-568 | Closed loop stays on the runtime guard flag | Fingerprint is a collapsed hash. Unconfirmed is not a pass only while the flag is on. Over-cap is not a DLP product. block-experimental is the block name while the flag is on. No new flag or command. | APPROVED
D-70 | phase-569 | Adoption helpers stay off without the flag | Tour writes nothing. Stack notes do not suppress findings. Digest reads a local file and does not fetch. No grade, no recall number, and no SOC2 claim. | APPROVED
D-72 | phase-571 | Section G stays behind one flag and does not change the default scan | Each G item is a local check or an explicit non-goal. G36 and G37 stay not claimed. Workflows are not edited. No new host. | APPROVED
D-73 | phase-572 | Section H package and framework checks stay on the section G flag | No new flag or command. H2, H3, H4, H6, H25, and H52 are not repeated. Scripts are not executed. Default scan findings stay the same. | APPROVED

D-74 | phase-573 | Section H auth, CI text, and output stay on the section G flag | No new flag, command, or workflow. H52 and H60 are not built. The schema adds no required field. A missing cache throws only when the offline marker is present, and nothing is fetched. Default scan findings stay the same. | APPROVED
