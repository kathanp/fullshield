# FullShield public benchmark

> **UNREVIEWED DRAFT.** Every `bench/*/ground-truth.json` still has `"reviewed": false`.
> Do not cite precision, recall, or headline counts from this file until the human flips that flag.

- FullShield version: 0.1.1
- Generated: 2026-10-15T16:45:11.220Z
- Matching: same class + same file, line within ±3
- Scan: `node dist/cli/index.js scan <app> --json --offline-safe`
- False positives = scanner findings that did not match a labeled ground-truth entry. The labeled set is a small cited subset of each app’s documented bugs, so unmatched deps/config/secrets hits count as FP even when they are real issues.

## nodegoat

- Repo: https://github.com/OWASP/NodeGoat.git
- Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Scan time: 1466 ms
- Ground truth reviewed: false
- Findings emitted: 373
- True positives: 4
- False positives: 369
- Misses: 1
- Precision: 1.1%
- Recall: 80.0%

| class | truth | TP | FP | misses |
|---|---:|---:|---:|---:|
| nosqli | 1 | 1 | 0 | 0 |
| ssrf | 1 | 1 | 0 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| secrets | 0 | 0 | 1 | 0 |
| deps | 0 | 0 | 359 | 0 |
| config | 0 | 0 | 7 | 0 |
| other | 2 | 1 | 2 | 1 |

## juice-shop

- Repo: https://github.com/juice-shop/juice-shop.git
- Commit: `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`
- Scan time: 3877 ms
- Ground truth reviewed: false
- Findings emitted: 33
- True positives: 2
- False positives: 31
- Misses: 1
- Precision: 6.1%
- Recall: 66.7%

| class | truth | TP | FP | misses |
|---|---:|---:|---:|---:|
| sqli | 2 | 2 | 4 | 0 |
| path | 0 | 0 | 3 | 0 |
| ssrf | 0 | 0 | 1 | 0 |
| redirect | 1 | 0 | 0 | 1 |
| secrets | 0 | 0 | 8 | 0 |
| deps | 0 | 0 | 1 | 0 |
| config | 0 | 0 | 6 | 0 |
| auth | 0 | 0 | 2 | 0 |
| other | 0 | 0 | 6 | 0 |

## dvna

- Repo: https://github.com/appsecco/dvna.git
- Commit: `9ba473add536f66ac9007966acb2a775dd31277a`
- Scan time: 790 ms
- Ground truth reviewed: false
- Findings emitted: 19
- True positives: 4
- False positives: 15
- Misses: 1
- Precision: 21.1%
- Recall: 80.0%

| class | truth | TP | FP | misses |
|---|---:|---:|---:|---:|
| sqli | 1 | 1 | 0 | 0 |
| cmdi | 1 | 1 | 0 | 0 |
| xss | 0 | 0 | 6 | 0 |
| redirect | 1 | 1 | 0 | 0 |
| deps | 0 | 0 | 5 | 0 |
| config | 0 | 0 | 4 | 0 |
| other | 2 | 1 | 0 | 1 |

## Known misses

| app | class | file:line | why |
|---|---|---|---|
| nodegoat | other | `app/routes/session.js:64` | log forging is not a shipped SAST class |
| juice-shop | redirect | `routes/redirect.ts:18` | not detected at the documented file/line (±3) |
| dvna | other | `core/appHandler.js:218` | no SAST-DESER rule in this release (Phase 29) |
