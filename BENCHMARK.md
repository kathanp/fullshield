# FullShield public benchmark

> These counts show what FullShield reports on known vulnerable practice apps. They are not accuracy scores. Bug lists and labels are not human-reviewed.

Precision is not sampled. `"reviewed"` stays false on every `bench/*/ground-truth.json`.

Counts below are `scan --json --offline-safe` on Node 22.23.3, 2026-11-04. The same totals were reported by tag `v3.6.0` and by this branch. They are report counts, not a score.

| app | commit | findings |
|---|---|---:|
| NodeGoat | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 273 |
| Juice Shop | `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4` | 105 |
| DVNA | `9ba473add536f66ac9007966acb2a775dd31277a` | 23 |
| goof | `add14ba59e98240d9e00a235dd7d42cd61ae9912` | 274 |
| vulnerable-node | `d68f2a3c9277ece2c2feb9976052033bdecd7fbe` | 65 |
