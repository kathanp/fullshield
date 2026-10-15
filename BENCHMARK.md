# FullShield public benchmark

> **UNREVIEWED DRAFT.** Every `bench/*/ground-truth.json` still has `"reviewed": false`.
> Do not cite precision, recall, or headline counts from this file until the human flips that flag.

- FullShield version: 0.1.1
- Generated: 2026-10-15T18:52:47.539Z
- Matching: same class + same file, line within ±3
- Recall: in-scope ground-truth entries only
- Precision: `realIssue / (realIssue + falsePositive)` on unmatched findings listed in `bench/<app>/triage.json`. `unsure` is excluded from the denominator and counted separately.
- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`

## nodegoat

- Repo: https://github.com/OWASP/NodeGoat.git
- Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Scan time: 1569 ms
- Ground truth reviewed: false
- Ground truth entries: 7 in-scope / 9 out-of-scope
- Findings emitted: 379
- In-scope true positives: 5
- In-scope misses: 2
- Unmatched findings (triaged): 374
- Recall (in-scope): 71.4%
- Precision (triaged): 99.5% (368 realIssue / 2 falsePositive; 4 unsure excluded)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| nosqli | 1 | 1 | 0 | 0 |
| xss | 1 | 0 | 0 | 1 |
| ssrf | 1 | 1 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| eval | 1 | 1 | 0 | 0 |
| secrets | 0 | 0 | 2 | 0 |
| deps | 1 | 0 | 0 | 1 |
| config | 1 | 1 | 0 | 0 |

## juice-shop

- Repo: https://github.com/juice-shop/juice-shop.git
- Commit: `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`
- Scan time: 3639 ms
- Ground truth reviewed: false
- Ground truth entries: 12 in-scope / 104 out-of-scope
- Findings emitted: 73
- In-scope true positives: 9
- In-scope misses: 3
- Unmatched findings (triaged): 64
- Recall (in-scope): 75.0%
- Precision (triaged): 88.4% (38 realIssue / 5 falsePositive; 21 unsure excluded)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| sqli | 2 | 2 | 0 | 0 |
| nosqli | 3 | 2 | 0 | 1 |
| xss | 1 | 0 | 0 | 1 |
| redirect | 2 | 1 | 0 | 1 |
| eval | 1 | 1 | 0 | 0 |
| secrets | 0 | 0 | 5 | 0 |
| deps | 1 | 1 | 0 | 0 |
| config | 2 | 2 | 0 | 0 |

## dvna

- Repo: https://github.com/appsecco/dvna.git
- Commit: `9ba473add536f66ac9007966acb2a775dd31277a`
- Scan time: 750 ms
- Ground truth reviewed: false
- Ground truth entries: 10 in-scope / 7 out-of-scope
- Findings emitted: 23
- In-scope true positives: 8
- In-scope misses: 2
- Unmatched findings (triaged): 15
- Recall (in-scope): 80.0%
- Precision (triaged): 90.0% (9 realIssue / 1 falsePositive; 5 unsure excluded)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| sqli | 1 | 1 | 0 | 0 |
| cmdi | 1 | 1 | 0 | 0 |
| xss | 2 | 2 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| eval | 1 | 1 | 0 | 0 |
| crypto | 1 | 1 | 0 | 0 |
| secrets | 1 | 1 | 1 | 0 |
| deps | 1 | 0 | 0 | 1 |
| config | 1 | 0 | 0 | 1 |

## Known misses (in-scope only)

| app | class | file:line | why |
|---|---|---|---|
| nodegoat | xss | `app/views/layout.html:75` | A3: stored XSS — profile firstName/lastName rendered unescaped in the layout nav. |
| nodegoat | deps | `package.json:18` | A9: marked@0.3.5 is a known-vulnerable markdown parser used to render user memos (XSS). |
| juice-shop | nosqli | `routes/updateProductReviews.ts:18` | NoSQL injection updating reviews by _id with multi:true. |
| juice-shop | redirect | `lib/insecurity.ts:136` | Redirect allowlist is bypassable via String.includes (redirectChallenge). |
| juice-shop | xss | `routes/trackOrder.ts:17` | Reflected XSS in track-order id (iframe javascript:alert). |
| dvna | config | `core/appHandler.js:197` | A6: calculator error path leaks a stack trace; mathjs.eval of attacker input. |
| dvna | deps | `package.json:25` | A9: mathjs version used by the calculator is a known RCE (eval sandbox escape). |
