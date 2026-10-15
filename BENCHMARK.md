# FullShield public benchmark

> **UNREVIEWED DRAFT.** Every `bench/*/ground-truth.json` still has `"reviewed": false`.
> Do not cite precision, recall, or headline counts from this file until the human flips that flag.

- FullShield version: 0.1.1
- Generated: 2026-10-15T19:42:05.735Z
- Matching: same class + same file, line within ±3
- In-scope score: true positives / in-scope ground-truth entries (unreviewed).
- Line attribution: a file-level (no-line) finding plus a later comment/line number on the same file is **not** counted as a recall gain.
- Precision: self-triaged, unverified. `realIssue / (realIssue + falsePositive)` on unmatched findings listed in `bench/<app>/triage.json`. `unsure` is excluded from the denominator and counted separately per app.
- Holdout apps are scored the same way. A seen holdout was used to find engine gaps; an untouched holdout is scanned once and does not drive rule changes.
- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`

## nodegoat

- Repo: https://github.com/OWASP/NodeGoat.git
- Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Scan time: 1652 ms
- Ground truth reviewed: false
- Ground truth entries: 7 in-scope / 9 out-of-scope
- Findings emitted: 379
- In-scope true positives: 5
- In-scope misses: 1
- Line-attribution only (not a recall gain): 1 — server.js:10 (config)
- Unmatched findings (triaged): 374
- In-scope true positives / in-scope truth: 5/7
- Precision: self-triaged, unverified (368 realIssue / 2 falsePositive; 4 unsure)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| nosqli | 1 | 1 | 0 | 0 |
| xss | 1 | 0 | 0 | 1 |
| ssrf | 1 | 1 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| eval | 1 | 1 | 0 | 0 |
| secrets | 0 | 0 | 2 | 0 |
| deps | 1 | 1 | 0 | 0 |
| config | 1 | 0 | 0 | 0 |

## juice-shop

- Repo: https://github.com/juice-shop/juice-shop.git
- Commit: `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`
- Scan time: 3718 ms
- Ground truth reviewed: false
- Ground truth entries: 12 in-scope / 104 out-of-scope
- Findings emitted: 75
- In-scope true positives: 9
- In-scope misses: 3
- Unmatched findings (triaged): 66
- In-scope true positives / in-scope truth: 9/12
- Precision: self-triaged, unverified (38 realIssue / 5 falsePositive; 23 unsure)

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
- Scan time: 783 ms
- Ground truth reviewed: false
- Ground truth entries: 10 in-scope / 7 out-of-scope
- Findings emitted: 23
- In-scope true positives: 9
- In-scope misses: 1
- Unmatched findings (triaged): 14
- In-scope true positives / in-scope truth: 9/10
- Precision: self-triaged, unverified (8 realIssue / 1 falsePositive; 5 unsure)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| sqli | 1 | 1 | 0 | 0 |
| cmdi | 1 | 1 | 0 | 0 |
| xss | 2 | 2 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| eval | 1 | 1 | 0 | 0 |
| crypto | 1 | 1 | 0 | 0 |
| secrets | 1 | 1 | 1 | 0 |
| deps | 1 | 1 | 0 | 0 |
| config | 1 | 0 | 0 | 1 |

## goof (seen holdout)

- Repo: https://github.com/snyk-labs/nodejs-goof.git
- Commit: `add14ba59e98240d9e00a235dd7d42cd61ae9912`
- Seen holdout: yes. Engine gaps were taken from this app; do not count this re-run as a recall gain.
- Scan time: 462 ms
- Ground truth reviewed: false
- Ground truth entries: 11 in-scope / 6 out-of-scope
- Findings emitted: 110
- In-scope true positives: 9
- In-scope misses: 2
- Unmatched findings (triaged): 101
- In-scope true positives / in-scope truth: 9/11
- Precision: self-triaged, unverified (96 realIssue / 1 falsePositive; 4 unsure)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| nosqli | 1 | 0 | 0 | 1 |
| cmdi | 1 | 1 | 0 | 0 |
| path | 1 | 1 | 0 | 0 |
| xss | 2 | 2 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| proto | 1 | 1 | 0 | 0 |
| secrets | 1 | 1 | 1 | 0 |
| deps | 2 | 1 | 0 | 1 |
| config | 1 | 1 | 0 | 0 |

## vulnerable-node (holdout)

- Repo: https://github.com/cr0hn/vulnerable-node.git
- Commit: `d68f2a3c9277ece2c2feb9976052033bdecd7fbe`
- Holdout: yes. Untouched. Do not change rules based on this app.
- Scan time: 463 ms
- Ground truth reviewed: false
- Ground truth entries: 12 in-scope / 9 out-of-scope
- Findings emitted: 56
- In-scope true positives: 9
- In-scope misses: 3
- Unmatched findings (triaged): 47
- In-scope true positives / in-scope truth: 9/12
- Precision: self-triaged, unverified (16 realIssue / 2 falsePositive; 29 unsure)

| class | in-scope truth | TP | triaged FP | in-scope misses |
|---|---:|---:|---:|---:|
| sqli | 3 | 3 | 0 | 0 |
| nosqli | 2 | 0 | 0 | 2 |
| cmdi | 1 | 1 | 0 | 0 |
| path | 1 | 1 | 0 | 0 |
| xss | 1 | 1 | 0 | 0 |
| ssrf | 1 | 1 | 0 | 0 |
| jwt | 1 | 1 | 0 | 0 |
| proto | 1 | 1 | 0 | 0 |
| secrets | 0 | 0 | 2 | 0 |
| config | 1 | 0 | 0 | 1 |

## Known misses (in-scope only)

| app | class | file:line | why |
|---|---|---|---|
| nodegoat | xss | `app/views/layout.html:75` | A3: stored XSS — profile firstName/lastName rendered unescaped in the layout nav. |
| juice-shop | nosqli | `routes/updateProductReviews.ts:18` | NoSQL injection updating reviews by _id with multi:true. |
| juice-shop | redirect | `lib/insecurity.ts:136` | Redirect allowlist is bypassable via String.includes (redirectChallenge). |
| juice-shop | xss | `routes/trackOrder.ts:17` | Reflected XSS in track-order id (iframe javascript:alert). |
| dvna | config | `core/appHandler.js:197` | A6: calculator error path leaks a stack trace; mathjs.eval of attacker input. |
| goof | nosqli | `routes/index.js:52` | NoSQL injection: login User.find() uses req.body.password as-is, so {"$gt":""} authenticates as admin. |
| goof | deps | `package.json:46` | st@0.2.4 is listed as an exploitable directory-traversal static server. |
| vulnerable-node | nosqli | `routes/shop.js:41` | NoSQL injection: /api/tags-filter passes req.body.tags into col.find() as the origin value. |
| vulnerable-node | nosqli | `routes/shop.js:58` | NoSQL injection: /api/meta assigns req.query.origin onto a Mongo filter. |
| vulnerable-node | config | `views/error.ejs:4` | Debug misconfiguration: error.stack is rendered when DEBUG_ERRORS=1. |
