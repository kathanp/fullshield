# Real-world benchmark: OWASP NodeGoat + DVNA

Scanned with the Phase 5 CLI (`node dist/cli/index.js scan --json`) on 2026-10-13.
Apps were cloned to `~/fullshield-bench/` (outside this repo). They were **not** installed or started.

| App | Commit / tree | Result file | Findings | Time |
|---|---|---|---|---|
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | clone at `~/fullshield-bench/NodeGoat` | `results/nodegoat-phase5.json` | 392 | ~135s (OSV) |
| [appsecco/dvna](https://github.com/appsecco/dvna) | clone at `~/fullshield-bench/dvna` | `results/dvna-phase5.json` | 9 | <2s (no lockfile) |

Rules were **not** tuned while classifying the Phase 5 output. In-scope misses and false positives listed below were reproduced as fixtures and fixed in the same `bench-1` commit after this analysis.

---

## OWASP NodeGoat

Known issues are taken from NodeGoat's own tutorials (`app/views/tutorial/`) and the vulnerable code they point at.

### Detected (true positives)

| Known issue | Tutorial | FullShield | Where |
|---|---|---|---|
| A1 Server-side JS injection | `eval(req.body.preTax)` etc. | `SAST-EVAL-001` ×3 | `app/routes/contributions.js:32-34` |
| A10 Unvalidated redirect | `res.redirect(req.query.url)` | `SAST-REDIRECT-001` | `app/routes/index.js:72` |
| A9 Vulnerable components | old `lodash`, `marked`, `minimist`, `handlebars`, … | `DEPS-VULN-001` ×320 | `package-lock.json` |
| A5 Missing helmet / security headers | helmet require and `app.use(helmet…)` are commented out in `server.js` | `CONFIG-HELMET-001` | `server.js` |
| A2 / A5 No rate limit on auth | `/login`, `/signup` | `CONFIG-RATELIMIT-001` ×4 | `app/routes/index.js` |
| A6 Error stack leak | | `CONFIG-ERRSTACK-001` | `app/routes/error.js:8` |
| A6 Committed TLS private key | demo cert in-tree | `SECRET-PRIVKEY-001` | `artifacts/cert/server.key` |

### Missed — in scope of current rules (single-function taint, §4.3 / §4.4)

| Known issue | Why in scope | Phase 5 |
|---|---|---|
| A1 / tutorial SSRF: `needle.get(req.query.url + req.query.symbol)` in `app/routes/research.js` | Same-function taint into an HTTP client; `SAST-SSRF-001` already lists `fetch` / `axios` / `http` | **Miss** — `needle` was not treated as an HTTP lib |

### Missed — out of scope (see Known misses)

A1 NoSQL `$where` interpolation in `app/data/allocations-dao.js` (taint crosses route → DAO), A1 log injection, A2 session/password policy, A3 XSS (Swig `{{ }}` is HTML-escaped; leftover risk is URL-context encoding in `profile.html`, not `{{{` / `<%-`), A4 IDOR, A7 missing function-level access, A8 CSRF (`csurf` commented out), ReDoS tutorial.

### False positives

| Finding | Why it is a false positive |
|---|---|
| `SECRET-DBURL-001` ×2 on `README.md:61` and `:135` | Docs example `mongodb://<username>:<password>@…` — angle-bracket placeholders, not a secret |
| `DEPS-TYPOSQUAT-001` ×18 | Legitimate transitive packages 1 edit from a popular name (`tmp`/`tap`, `csrf`/`csurf`, `utile`/`util`, `is-typedarray`/`is-typed-array`, 1-character names `i`/`d`, …) |
| `CONFIG-HELMET-001` on `app/routes/tutorial.js` | File only does `express.Router()`, not `express()`. Helmet belongs on the app, which is already flagged on `server.js` |

Not counted as false positives: 320 OSV hits (the lockfile really is that old), `DEPS-DEPRECATED-001` (info), `CONFIG-INSTALLSCRIPT-001` on Cypress, or the committed `server.key`.

---

## DVNA (Damn Vulnerable Node Application)

Known issues are taken from `docs/solution/*.md` and `core/appHandler.js`.

### Detected (true positives)

| Known issue | FullShield | Where |
|---|---|---|
| A1 SQL injection (`sequelize.query("…'" + req.body.login + "'")`) | `SAST-SQLI-001` | `core/appHandler.js:11` |
| A1 Command injection (`exec('ping -c 2 ' + req.body.address)`) | `SAST-CMDI-001` | `core/appHandler.js:39` |
| Unvalidated redirect (`res.redirect(req.query.url)`) | `SAST-REDIRECT-001` | `core/appHandler.js:188` |
| Missing helmet on the real app | `CONFIG-HELMET-001` | `server.js` |
| No rate limit on `/login` | `CONFIG-RATELIMIT-001` ×2 | `routes/main.js` |
| Dockerfile runs as root | `CONFIG-DOCKER-ROOT-001` | `Dockerfile` |

No `package-lock.json` in the clone, so the deps module did not run (A9 known-vulnerable components: **not evaluated**).

### Missed — in scope of current rules

| Known issue | Why in scope | Phase 5 |
|---|---|---|
| A1 code injection: `mathjs.eval(req.body.eqn)` | Same-function taint; `SAST-EVAL-001` is `eval` / `new Function` / `vm.runInNewContext` | **Miss** — only bare `eval` Identifier was matched |
| A7 XSS: `<%- output.searchTerm %>` (and stored `<%- output.products[i].… %>`) in `views/app/products.ejs` | §4.3 `SAST-XSS-001` explicitly includes template `{{{ }}}` / `<%- %>` | **Miss** — SAST only parsed JS/TS, and the XSS visitor only looked at `res.send` / `res.write` |

### Missed — out of scope (see Known misses)

A2 broken auth, A3 sensitive data, A4 XXE (`libxmljs` `noent:true`), A5 IDOR / broken access, A8 insecure deserialization (`node-serialize`), A10 logging, CSRF. Insecure deserialization is mentioned in §1 product scope but is **not** a §4.3 v1 rule.

### False positives

| Finding | Why it is a false positive |
|---|---|
| `CONFIG-HELMET-001` on `routes/app.js` and `routes/main.js` | Both files only call `require('express').Router()` |

---

## Known misses (out of scope — do not tune Core rules for these)

- **Cross-file taint:** NodeGoat allocations `$where` (`req.query.threshold` in the route, interpolated in `allocations-dao.js`). Needs Phase 13 call-graph taint.
- **Business logic / access control:** IDOR, missing function-level access, CSRF, session fixation, password policy, broken auth.
- **Template XSS that is not `{{{` / `<%-`:** NodeGoat Swig `{{ }}` (auto-escaped) and URL-context encoding.
- **XXE, insecure deserialization, ReDoS, log injection** — no Core rule id.
- **HTTP clients beyond the SSRF allow-list after the bench-1 fix** still will not invent a generic `*.get(url)` rule (`Map.get` / `cache.get` would explode FPs).
- **Dependency reachability:** NodeGoat's 320 OSV findings are untriaged; most are transitive / dev (Cypress, Grunt). Phase 13.

---

## bench-1 rule fixes (after the analysis above)

New fixtures only; existing `expected-findings.json` rows were not removed or weakened.

| Gap | New fixture | Rule change |
|---|---|---|
| `mathjs.eval(req.body.eqn)` | `vulnerable-app` `mathjs.eval(...)` | `SAST-EVAL-001` treats callee name `eval` (member or identifier) |
| `needle.get(taintedUrl)` | `vulnerable-app` research-style `needle.get` | `SAST-SSRF-001` HTTP libs include `needle` / `got` / `request` / `superagent` / `undici` |
| EJS `<%- expr %>` | `vulnerable-app/views/hello.ejs` | `SAST-XSS-001` scans `.ejs`/`.hbs`/`.njk`; skips `<%- include` |
| Docs DB URL placeholders | `clean-app/README.md` + source comment | `SECRET-DBURL-001` skips `<placeholder>` / `{placeholder}` passwords |
| Typosquat on legit / hyphen / short names | unit negatives; `tmp` listed on clean-app | Direct `package.json` deps only; min length 4; hyphen-normalized equality skipped; small legit-collision set |
| Helmet on `Router()` files | `clean-app/src/router.js` | `CONFIG-HELMET-001` requires an `express()` app factory call |

### Detection counts (Phase 5 baseline → after bench-1)

Re-scanned after the fixes; original JSON kept as `*-phase5.json`. Post-fix JSON: `*-bench1.json`.

| App | Phase 5 findings | After bench-1 | Delta |
|---|---|---|---|
| NodeGoat | 392 | 372 | −20 |
| DVNA | 9 | 14 | +5 |

NodeGoat: +1 `SAST-SSRF-001` on `app/routes/research.js:16`; −2 `SECRET-DBURL-001` README placeholders; −18 `DEPS-TYPOSQUAT-001`; −1 `CONFIG-HELMET-001` on `tutorial.js`. Helmet on `server.js` remains a true positive.

DVNA: +1 `SAST-EVAL-001` on `mathjs.eval`; +6 `SAST-XSS-001` on `views/app/products.ejs` (searchTerm + stored product fields); −2 `CONFIG-HELMET-001` on Router files. Helmet on `server.js` remains.

In-scope known-vuln recall after bench-1: NodeGoat eval + redirect + SSRF + A9 deps + helmet/rate-limit/err.stack/privkey. DVNA SQLi + CMDi + redirect + eval + XSS + helmet/rate-limit/docker-root.

This table is updated again after Phase 7 and Phase 10.
