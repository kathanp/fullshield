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

- **Cross-file taint:** NodeGoat allocations `$where` is detected as of Phase 13 (`SAST-NOSQLI-001` on `app/data/allocations-dao.js:77`, trace spans the route + DAO). Remaining misses: dynamic/`eval`-built callees, TS path aliases, hops > 5.
- **Business logic / access control:** IDOR, missing function-level access, CSRF, session fixation, password policy, broken auth.
- **Template XSS that is not `{{{` / `<%-`:** NodeGoat Swig `{{ }}` (auto-escaped) and URL-context encoding.
- **XXE, insecure deserialization, ReDoS, log injection** — no Core rule id.
- **HTTP clients beyond the SSRF allow-list after the bench-1 fix** still will not invent a generic `*.get(url)` rule (`Map.get` / `cache.get` would explode FPs).
- **Dependency reachability:** harden-3 classifies transitives on a lockfile path from a production-imported direct dep as `reachable-via-dependency` (severity kept). Affected-function lists from OSV/GHSA are not yet used (import+any-call ≈ reachable). See After harden-3.

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

### After Phase 7

| App | Phase 5 | bench-1 | Phase 7 | Notes |
|---|---|---|---|---|
| NodeGoat | 392 | 372 | 372 | Fixer does not change detection. Rule mix unchanged vs bench-1. |
| DVNA | 9 | 14 | 14 | Same as bench-1. |

### After Phase 10 (end of Core)

| App | Phase 5 | bench-1 | Phase 7 | Phase 10 |
|---|---|---|---|---|
| NodeGoat | 392 | 372 | 372 | 372 |
| DVNA | 9 | 14 | 14 | 14 |

Phases 8–10 added runtime, init/notify, and docs. They do not change static detection. JSON: `results/*-phase10.json`.

### After harden-1

Typosquat no longer uses a named collision allowlist. A name is flagged only when it is 1 edit from `POPULAR_PACKAGES` **and** is not itself in the larger static `TOP_PACKAGES` list (still direct `package.json` deps only, min length 4, hyphen-normalized equality skipped).

| App | Phase 5 | bench-1 | Phase 10 | harden-1 | Notes |
|---|---|---|---|---|---|
| NodeGoat | 392 | 372 | 372 | 372 | 0 typosquat findings (same as bench-1). The 18 Phase-5 FPs stay gone because those names are either transitive, short, hyphen-only, or in `TOP_PACKAGES` (`tmp`, `csrf`, `utile`, …). No new FPs. |
| DVNA | 9 | 14 | 14 | 14 | Unchanged. No lockfile, so deps/typosquat still not evaluated. |

False-positive change vs Phase 10: **none**. False-positive change vs Phase 5: still −18 typosquat, −2 placeholder DB URLs, −1/−2 helmet-on-Router. JSON: `results/*-harden1.json`.

### After harden-2

`DEPS-NOLOCK-001` (info) when `package.json` exists and no lockfile is present. Exact versions pinned in `package.json` are still queried on OSV. `TOP_PACKAGES` names that were added only because they appeared in NodeGoat/DVNA (`swig`, `forever`, `consolidate`, `mathjs`, `libxmljs`, `node-serialize`, `grunt-contrib-*`, `selenium-webdriver`, …) were removed. Source/date is documented at the top of `src/modules/deps/topPackages.ts`.

| App | harden-1 | harden-2 | Notes |
|---|---|---|---|
| NodeGoat | 372 | 372 | Still 0 typosquat findings. Removing the benchmark-only top-package names did **not** add FPs (those names were not 1-edit from `POPULAR_PACKAGES` as *direct* deps, or they remain in the general list). |
| DVNA | 14 | 19 | +1 `DEPS-NOLOCK-001` (info, true: no lockfile). +4 `DEPS-VULN-001` on exact pins: `mathjs@3.10.1` ×3, `node-serialize@0.0.4` ×1 (true positives; previously skipped). No new typosquat FPs. |

Typosquat false-positive change vs harden-1: **none**. JSON: `results/*-harden2.json`.

### After Phase 13

Cross-file taint (call graph, depth 5) + dependency reachability + CycloneDX 1.5 SBOM.

**NodeGoat 372 → 373.** The extra finding is a true positive: `SAST-NOSQLI-001` on `app/data/allocations-dao.js:77` (`$where` interpolates `req.query.threshold` from `app/routes/allocations.js`). Trace spans 2 files (route → DAO method on a `new AllocationsDAO()` instance). No new false positives.

**Reachability (NodeGoat `DEPS-VULN-001` ×320, same OSV hits as harden-2):**

| Class | Count | Severity change | Why |
|---|---|---|---|
| `reachable` (imported and called) | 13 | none | `async`, `body-parser`, `marked`, `mongodb`, `swig`, `express` |
| `imported-not-called` | 4 | −1 | `underscore` is imported but no call was found |
| `not-imported` | 303 | −2 | transitive / unused lockfile packages (Cypress, Grunt, …) |

307 of 320 dependency alerts were downgraded. High+critical on the whole scan: **210 → 16** (1 critical: committed TLS key; 6 SAST/high; 9 remaining high `DEPS-VULN-001`, of which 7 are reachable and 2 are `underscore` after −1 from critical). `DEPS-VULN-001` severity mix: critical 33 / high 171 / medium 98 / low 18 → high 9 / medium 37 / low 164 / info 110.

**DVNA 19 → 19.** The 4 exact-pin `DEPS-VULN-001` (`mathjs@3.10.1` ×3, `node-serialize@0.0.4`) are `reachable` (the app imports them), so they were not downgraded. SQLI/CMDI stay intra-function TPs. No new FPs.

| App | harden-2 | Phase 13 | Notes |
|---|---|---|---|
| NodeGoat | 372 | 373 | +1 `$where` TP. 303 not-imported OSV hits −2 severity; 4 imported-not-called −1. |
| DVNA | 19 | 19 | Unchanged count; pin vulns stay reachable. |

False-positive change vs harden-2: **none**. JSON: `results/*-phase13.json`.

### After harden-3

Phase 13 treated every non-imported package as `not-imported` (−2), including transitives of packages the app actually loads. That was wrong: `qs` runs when `express` runs.

**Corrected NodeGoat `DEPS-VULN-001` ×320** (same OSV hits; path roots are production sources only, not `test/`):

| Class | Count | Severity | Why |
|---|---|---|---|
| `reachable` | 12 | kept | production import + call (`express`, `marked`, `mongodb`, `swig`, `needle`, …) |
| `imported-not-called` | 4 | −1 | `underscore` imported in app code, no call |
| `reachable-via-dependency` | 84 | **kept** | lockfile path from an imported direct dep (e.g. `express > qs`, `swig > optimist > minimist`, `mongodb > mongodb-core > bson`) |
| `not-imported` | 220 | −2 | no path from any production-imported direct dep (Cypress/Grunt/selenium trees, unused directs, orphans) |

129 of the 320 are also **dev-only** (devDependency tree, no production import) → forced to **info** with a `dev-only` note. That overlay applies after reachability.

Whole-scan high+critical: Phase 13 **16 → 59**. The increase is the intended correction: 52 remaining high/critical `DEPS-VULN-001` (9 critical + 43 high), plus the same 1 secret + 6 SAST highs. Total findings stay 373. `async` drops out of `reachable` because only tests import it.

**DVNA 19 unchanged.** Four exact-pin vulns stay `reachable`. No lockfile graph.

False-positive change vs Phase 13: **none** (same finding set; severities of real runtime transitives went *up*). JSON: `results/*-harden3.json`.

### After Phase 11

`watch` does not change static detection. NodeGoat 373 / DVNA 19 unchanged vs harden-3.

### After Phase 12

`edge` is a live-URL command, not a repo scan. NodeGoat 373 / DVNA 19 unchanged vs harden-3.

### After Phases 14–16

AI is opt-in and fixture-only in CI. Default `scan` of NodeGoat/DVNA does not call a model and does not add `source: ai` findings. NodeGoat 373 / DVNA 19 unchanged vs harden-3. High+critical remains **59** (honest harden-3 correction).

### After harden-4

Yarn and pnpm lockfiles now parse real dependency edges. Formats without parsed edges stay `reachability-unknown` (severity kept) instead of being downgraded as `not-imported`.

**NodeGoat 373 / high+critical 59 unchanged** (npm `package-lock.json`, same 320 OSV hits: reachable 12, imported-not-called 4, reachable-via-dependency 84, not-imported 220). **DVNA 19 unchanged** (no lockfile). JSON: `results/*-harden4.json`.

Live Ollama smoke (not this default scan) is in [`AI-REPORT.md`](AI-REPORT.md).

### After Phase 17

Experimental RASP is off by default and is not a scan module. Default `scan` of NodeGoat/DVNA is unchanged.

**NodeGoat 373 / high+critical 59 unchanged. DVNA 19 unchanged.** JSON: `results/*-phase17.json`.

RASP corpus (not these repo scans): attack **41/43 (95.3%)** blocked, benign **0/26**. Two attack misses are IPv6 SSRF URLs (`http://[::1]/`, `http://[fd12:3456:789a::1]/`) — `URL.hostname` keeps brackets and the private-range check did not strip them. Still behind `FULLSHIELD_EXPERIMENTAL_RASP`.

### After harden-5

SSRF host normalization + PayloadsAllTheThings corpora. Default scan unchanged.

**NodeGoat 373 / high+critical 59 unchanged. DVNA 19 unchanged.** JSON: `results/*-harden5.json`.

RASP corpus: attack **173/181 (95.6%)** — sql 40/44, shell 43/47, path 51/51, ssrf 39/39. Benign **0/621**. Inventory: [`RASP-SINKS.md`](../RASP-SINKS.md).

### After Phase 18

Virtual patches / honey / egress are experimental runtime/CLI and do not change default `scan` findings.

**NodeGoat 373 / high+critical 59 unchanged. DVNA 19 unchanged.** JSON: `results/*-phase18.json`.
