# FullShield public benchmark

> **UNREVIEWED DRAFT.** Every `bench/*/ground-truth.json` still has `"reviewed": false`.
> Do not cite precision, recall, or headline counts from this file until the human flips that flag.

- FullShield version: 0.1.1
- Generated: 2026-10-15T17:04:00.606Z
- Matching: same class + same file, line within ±3
- Recall: in-scope ground-truth entries only
- Precision: `realIssue / (realIssue + falsePositive)` on unmatched findings listed in `bench/<app>/triage.json`. `unsure` is excluded from the denominator and counted separately.
- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`

## nodegoat

- Repo: https://github.com/OWASP/NodeGoat.git
- Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Scan time: 1369 ms
- Ground truth reviewed: false
- Ground truth entries: 7 in-scope / 9 out-of-scope
- Findings emitted: 373
- In-scope true positives: 4
- In-scope misses: 3
- Unmatched findings (triaged): 369
- Recall (in-scope): 57.1%
- Precision (triaged): 100.0% (366 realIssue / 0 falsePositive; 3 unsure excluded)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| nosqli | 1 | 1 | 0 | 0 |
| xss | 1 | 0 | 0 | 1 |
| ssrf | 1 | 1 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| eval | 1 | 1 | 0 | 0 |
| deps | 1 | 0 | 0 | 1 |
| config | 1 | 0 | 0 | 1 |

## juice-shop

- Repo: https://github.com/juice-shop/juice-shop.git
- Commit: `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`
- Scan time: 3522 ms
- Ground truth reviewed: false
- Ground truth entries: 12 in-scope / 104 out-of-scope
- Findings emitted: 33
- In-scope true positives: 4
- In-scope misses: 8
- Unmatched findings (triaged): 29
- Recall (in-scope): 33.3%
- Precision (triaged): 54.5% (6 realIssue / 5 falsePositive; 18 unsure excluded)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| sqli | 2 | 2 | 0 | 0 |
| nosqli | 3 | 0 | 0 | 3 |
| xss | 1 | 0 | 0 | 1 |
| redirect | 2 | 0 | 0 | 2 |
| eval | 1 | 1 | 0 | 0 |
| secrets | 0 | 0 | 5 | 0 |
| deps | 1 | 1 | 0 | 0 |
| config | 2 | 0 | 0 | 2 |

## dvna

- Repo: https://github.com/appsecco/dvna.git
- Commit: `9ba473add536f66ac9007966acb2a775dd31277a`
- Scan time: 743 ms
- Ground truth reviewed: false
- Ground truth entries: 10 in-scope / 7 out-of-scope
- Findings emitted: 19
- In-scope true positives: 6
- In-scope misses: 4
- Unmatched findings (triaged): 13
- Recall (in-scope): 60.0%
- Precision (triaged): 100.0% (9 realIssue / 0 falsePositive; 4 unsure excluded)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| sqli | 1 | 1 | 0 | 0 |
| cmdi | 1 | 1 | 0 | 0 |
| xss | 2 | 2 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| eval | 1 | 1 | 0 | 0 |
| crypto | 1 | 0 | 0 | 1 |
| secrets | 1 | 0 | 0 | 1 |
| deps | 1 | 0 | 0 | 1 |
| config | 1 | 0 | 0 | 1 |

## Known misses (in-scope only)

| app | class | file:line | why |
|---|---|---|---|
| nodegoat | xss | `app/views/layout.html:75` | A3: stored XSS — profile firstName/lastName rendered unescaped in the layout nav. |
| nodegoat | config | `server.js:10` | A5: helmet security headers are commented out (x-powered-by, frameguard, HSTS, CSP). |
| nodegoat | deps | `package.json:18` | A9: marked@0.3.5 is a known-vulnerable markdown parser used to render user memos (XSS). |
| juice-shop | nosqli | `routes/trackOrder.ts:18` | NoSQL injection on order tracking via Mongo $where. |
| juice-shop | nosqli | `routes/showProductReviews.ts:36` | NoSQL $where on product reviews (sleep DoS / noSqlCommandChallenge). |
| juice-shop | nosqli | `routes/updateProductReviews.ts:18` | NoSQL injection updating reviews by _id with multi:true. |
| juice-shop | redirect | `routes/redirect.ts:18` | Open redirect: /redirect follows toUrl when allowlist uses includes(). |
| juice-shop | redirect | `lib/insecurity.ts:136` | Redirect allowlist is bypassable via String.includes (redirectChallenge). |
| juice-shop | xss | `routes/trackOrder.ts:17` | Reflected XSS in track-order id (iframe javascript:alert). |
| juice-shop | config | `server.ts:290` | Directory listing enabled on /ftp. |
| juice-shop | config | `server.ts:302` | Access logs served under /support/logs. |
| dvna | crypto | `core/authHandler.js:49` | A2: password reset token is md5(login), attacker-computable. |
| dvna | secrets | `server.js:24` | A2: express-session secret is the well-known 'keyboard cat'. |
| dvna | config | `core/appHandler.js:197` | A6: calculator error path leaks a stack trace; mathjs.eval of attacker input. |
| dvna | deps | `package.json:25` | A9: mathjs version used by the calculator is a known RCE (eval sandbox escape). |
