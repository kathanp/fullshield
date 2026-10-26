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
