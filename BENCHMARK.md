# FullShield public benchmark

> **UNREVIEWED DRAFT.** Every `bench/*/ground-truth.json` still has `"reviewed": false`.
> Do not cite precision, recall, or headline counts from this file until the human flips that flag.

- FullShield version: 1.2.0
- Generated: 2026-10-20T21:43:56.603Z
- Matching: same class + same file, line within ±3
- In-scope score: true positives / in-scope ground-truth entries (unreviewed).
- Line attribution: a file-level (no-line) finding plus a later comment/line number on the same file is **not** counted as a recall gain.
- Precision: not measured. `bench/<app>/triage.json` is self-triaged by the tool's author and is not used for any rate. Human sampling: `bench/precision/` (Phase 76).
- Precision is not sampled until a human labels findings.
- Holdout apps are scored the same way. A seen holdout was used to find engine gaps or to re-score after an authorized rule change.
- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`

## nodegoat

- Repo: https://github.com/OWASP/NodeGoat.git
- Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Scan time: 958 ms
- Ground truth reviewed: false
- Ground truth entries: 7 in-scope / 9 out-of-scope
- Findings emitted: 271
- In-scope true positives: 5
- In-scope misses: 1
- Line-attribution only (not a recall gain): 1 — server.js:10 (config)
- Unmatched findings (triaged): 266
- In-scope true positives / in-scope truth: 5/7
- Precision: not measured. `bench/<app>/triage.json` is self-triaged by the tool's author and is not used for any rate. Human sampling: `bench/precision/` (Phase 76).

| class | in-scope truth | TP | in-scope misses |
|---|---:|---:|---:|
| nosqli | 1 | 1 | 0 |
| xss | 1 | 0 | 1 |
| ssrf | 1 | 1 | 0 |
| redirect | 1 | 1 | 0 |
| eval | 1 | 1 | 0 |
| secrets | 0 | 0 | 0 |
| deps | 1 | 1 | 0 |
| config | 1 | 0 | 0 |

## juice-shop

- Repo: https://github.com/juice-shop/juice-shop.git
- Commit: `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`
- Scan time: 22340 ms
- Ground truth reviewed: false
- Ground truth entries: 12 in-scope / 104 out-of-scope
- Findings emitted: 105
- In-scope true positives: 10
- In-scope misses: 2
- Unmatched findings (triaged): 95
- In-scope true positives / in-scope truth: 10/12
- Precision: not measured. `bench/<app>/triage.json` is self-triaged by the tool's author and is not used for any rate. Human sampling: `bench/precision/` (Phase 76).

| class | in-scope truth | TP | in-scope misses |
|---|---:|---:|---:|
| sqli | 2 | 2 | 0 |
| nosqli | 3 | 3 | 0 |
| xss | 1 | 0 | 1 |
| redirect | 2 | 1 | 1 |
| eval | 1 | 1 | 0 |
| secrets | 0 | 0 | 0 |
| deps | 1 | 1 | 0 |
| config | 2 | 2 | 0 |

## dvna

- Repo: https://github.com/appsecco/dvna.git
- Commit: `9ba473add536f66ac9007966acb2a775dd31277a`
- Scan time: 473 ms
- Ground truth reviewed: false
- Ground truth entries: 10 in-scope / 7 out-of-scope
- Findings emitted: 23
- In-scope true positives: 9
- In-scope misses: 1
- Unmatched findings (triaged): 14
- In-scope true positives / in-scope truth: 9/10
- Precision: not measured. `bench/<app>/triage.json` is self-triaged by the tool's author and is not used for any rate. Human sampling: `bench/precision/` (Phase 76).

| class | in-scope truth | TP | in-scope misses |
|---|---:|---:|---:|
| sqli | 1 | 1 | 0 |
| cmdi | 1 | 1 | 0 |
| xss | 2 | 2 | 0 |
| redirect | 1 | 1 | 0 |
| eval | 1 | 1 | 0 |
| crypto | 1 | 1 | 0 |
| secrets | 1 | 1 | 0 |
| deps | 1 | 1 | 0 |
| config | 1 | 0 | 1 |

## goof (seen holdout)

- Repo: https://github.com/snyk-labs/nodejs-goof.git
- Commit: `add14ba59e98240d9e00a235dd7d42cd61ae9912`
- Seen holdout: yes. Engine gaps were taken from this app; do not count this re-run as a recall gain.
- Scan time: 662 ms
- Ground truth reviewed: false
- Ground truth entries: 11 in-scope / 6 out-of-scope
- Findings emitted: 274
- In-scope true positives: 11
- In-scope misses: 0
- Unmatched findings (triaged): 263
- In-scope true positives / in-scope truth: 11/11
- Precision: not measured. `bench/<app>/triage.json` is self-triaged by the tool's author and is not used for any rate. Human sampling: `bench/precision/` (Phase 76).

| class | in-scope truth | TP | in-scope misses |
|---|---:|---:|---:|
| nosqli | 1 | 1 | 0 |
| cmdi | 1 | 1 | 0 |
| path | 1 | 1 | 0 |
| xss | 2 | 2 | 0 |
| redirect | 1 | 1 | 0 |
| proto | 1 | 1 | 0 |
| secrets | 1 | 1 | 0 |
| deps | 2 | 2 | 0 |
| config | 1 | 1 | 0 |

## vulnerable-node (seen holdout)

- Repo: https://github.com/cr0hn/vulnerable-node.git
- Commit: `d68f2a3c9277ece2c2feb9976052033bdecd7fbe`
- Seen holdout: yes. Re-scored after an authorized rule change; do not count this as a recall gain.
- Scan time: 721 ms
- Ground truth reviewed: false
- Ground truth entries: 12 in-scope / 9 out-of-scope
- Findings emitted: 65
- In-scope true positives: 11
- In-scope misses: 1
- Unmatched findings (triaged): 54
- In-scope true positives / in-scope truth: 11/12
- Precision: not measured. `bench/<app>/triage.json` is self-triaged by the tool's author and is not used for any rate. Human sampling: `bench/precision/` (Phase 76).

| class | in-scope truth | TP | in-scope misses |
|---|---:|---:|---:|
| sqli | 3 | 3 | 0 |
| nosqli | 2 | 2 | 0 |
| cmdi | 1 | 1 | 0 |
| path | 1 | 1 | 0 |
| xss | 1 | 1 | 0 |
| ssrf | 1 | 1 | 0 |
| jwt | 1 | 1 | 0 |
| proto | 1 | 1 | 0 |
| secrets | 0 | 0 | 0 |
| config | 1 | 0 | 1 |

## Known misses (in-scope only)

| app | class | file:line | why |
|---|---|---|---|
| nodegoat | xss | `app/views/layout.html:75` | A3: stored XSS — profile firstName/lastName rendered unescaped in the layout nav. |
| juice-shop | redirect | `lib/insecurity.ts:136` | Redirect allowlist is bypassable via String.includes (redirectChallenge). |
| juice-shop | xss | `routes/trackOrder.ts:17` | Reflected XSS in track-order id (iframe javascript:alert). |
| dvna | config | `core/appHandler.js:197` | A6: calculator error path leaks a stack trace; mathjs.eval of attacker input. |
| vulnerable-node | config | `views/error.ejs:4` | Debug misconfiguration: error.stack is rendered when DEBUG_ERRORS=1. |

## next.js

Not produced by `npm run bench:public`. Taken from `bench/perf-baseline.json`.

This is the completed run, not an OOM abort. `finished` is true. `measuredAt` is `2026-10-16T23:07:57.378Z`. Cold p50 is 71746.763708 ms (71.7 s). All five `statuses` are 1.
