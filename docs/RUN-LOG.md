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

## Restore 0.3.0

```
Phase restore-0.3.0 — match published 0.3.0
Branch/commit: restore-0.3.0 | pushed: no | merged into next: yes
Flag: none (published source)
Built: merge of v0.3.0 (91bbc6b). Phase 46 floor and Phase 47 console kept. Version set to 0.3.0.
Not done / limitations: dist differs from the npm tarball only in the console view, --all, and the Node 22.13 doctor floor. Branch coverage is 81.79% / 81.77%.
Tests added: 0 (source restored) | total: 817
default-scan-diff: DIFF 0.2.6 -> 0.3.0 totals nodegoat 379 -> 256, goof 354 -> 271. Unique keys identical.
verify: Node 22.23.3 tests 817, lines 92.57%, branches 81.79%. Node 24.22.0 tests 817, lines 92.55%, branches 81.77%. vulnerable-app 35, clean-app high/critical 0.
Benchmark impact: nodegoat 256, juice-shop 105, dvna 23, goof 271, vulnerable-node 61 (unreviewed)
Next CI: not pushed
Needs human decision: none
```

## Restore 0.4.0

```
Phase restore-0.4.0 — same-function Mongo filter
Branch/commit: restore-0.4.0 | pushed: no | merged into next: yes
Flag: none
Built: SAST-NOSQLI-001 reports a filter built from request input in the same function. Version stays 0.3.0.
Not done / limitations: stash docs were not copied. Unknown stash files: none.
Tests added: nosql-built-filter | total: 828
default-scan-diff: vulnerable-node 61 -> 63. Added SAST-NOSQLI-001 routes/shop.js:41 high and :58 high. Other apps unchanged.
verify: Node 22.23.3 tests 828, lines 92.62%, branches 82.06%. Node 24.22.0 tests 828, lines 92.61%, branches 82.03%. vulnerable-app 35, clean-app high/critical 0.
Benchmark impact: vulnerable-node 63 (unreviewed)
Next CI: not pushed
Needs human decision: none
```

## Phase 48

```
Phase 48 — Unused dependency removal
Branch/commit: phase-48 | pushed: no | merged into next: yes
Flag: none
Built: unused direct dependency count and fix --unsafe removal from package.json only.
Not done / limitations: devDependencies are not offered for removal. A lockfile with unknown edges produces no list.
Tests added: 2 (phase48-unused) | total: 830
default-scan-diff: EMPTY (base 146e09d head b835dc9; vulnerable-app 35, clean-app 0, nodegoat 256, juice-shop 105, dvna 23, goof 271, vulnerable-node 63)
verify: Node 22.23.3 tests 830, lines 92.61%, branches 82.13%. Node 24.22.0 tests 830, lines 92.6%, branches 82.11%. vulnerable-app 35, clean-app high/critical 0.
Benchmark impact: none expected (finding keys unchanged)
Next CI: not pushed
Needs human decision: none
```

## Docs reconcile

```
Phase docs-reconcile — stash notes that are still true
Branch/commit: docs-reconcile | pushed: no | merged into next: yes
Flag: none
Built: brought still-true sentences from the stash into errors, noise, Node 20, stabilization, demo, REVIEW, rules README, and CONTRIBUTING. Left out the 0.4.0 version line, the claim that Phase 47 is unbuilt, and the claim that confirm still runs on Node 20.
Not done / limitations: stash package.json, lockfile, CHANGELOG, README, and the spec were not touched.
Tests added: 0
default-scan-diff: EMPTY (base 43f8590 head a815b5a)
CI: `npm publish --dry-run` on next exits 1 when the version is already on npm. The job still packs the tarball and now treats that collision as expected. The version stays 0.3.0.
verify: docs only; scan keys are the gate
Benchmark impact: none
Next CI: not pushed
Needs human decision: none
```
