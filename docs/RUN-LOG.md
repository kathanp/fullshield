# Run log

0.8 reports for the 2026-10-18 run. Nothing is pushed.

## Phase 46 — Supported runtime and README version

```
Phase 46 — Supported runtime and README version
Branch/commit: phase-46 | pushed: no | merged into next: yes (fast-forward after this commit)
Flag: none
Built: locking test for engines >=22.13, doctor rejects Node 20.11, CI matrix is Node 22 and 24. README, SECURITY.md, and docs/NODE-20.md name that floor.
Not done / limitations: branch protection job names on GitHub are unchanged.
Tests added: 3 (phase46-runtime) plus the D1 assertion in the existing doctor test | total: 785
default-scan-diff: EMPTY (base 2fa8e71 head 7b78dc4; vulnerable-app, clean-app, nodegoat, juice-shop, dvna, goof, vulnerable-node identical)
verify: Node 22.23.3 tests 785, lines 92.49%, branches 82.29%, vulnerable-app 35, clean-app high/critical 0. Node 24.22.0 tests 785, lines 92.47%, branches 82.28%, vulnerable-app 35, clean-app high/critical 0.
Benchmark impact: none (no scanner change)
Next CI: not pushed
Needs human decision: none
```

## Phase 47 — Actionable console view

```
Phase 47 — Actionable console view
Branch/commit: phase-47 | pushed: no | merged into next: yes (fast-forward after this commit)
Flag: none (console only)
Built: D3 shown rule, package-name grouping, 20-row cap, --all. D4 accepts NodeGoat 36, goof 63, juice-shop 49, dvna 14, vulnerable-node 41. No row-count threshold.
Not done / limitations: grouped-row counts are from the 2026-10-18 offline-safe JSON, unreviewed.
Tests added: 5 (phase47-console) | total: 790
default-scan-diff: EMPTY (base 7b78dc4 head 8d3c2ad; vulnerable-app, clean-app, nodegoat, juice-shop, dvna, goof, vulnerable-node identical)
verify: Node 22.23.3 tests 790, lines 92.54%, branches 82.19%, vulnerable-app 35, clean-app high/critical 0. Node 24.22.0 tests 790, lines 92.53%, branches 82.17%, vulnerable-app 35, clean-app high/critical 0.
Benchmark impact: none (console only; JSON keys unchanged)
Next CI: not pushed
Needs human decision: none
```
