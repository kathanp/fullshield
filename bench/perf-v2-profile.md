# Phase 78 step 1 — Next.js cold scan profile

One run. Labeled unreviewed. Machine: local macOS, Node v22.23.3. Not a headline.

Command:

```
node --cpu-prof --cpu-prof-dir /tmp/fs78-prof --cpu-prof-name next-cold.cpuprofile dist/cli/index.js scan /Users/k244p/fullshield-bench/next --json --offline-safe
```

Checkout: `vercel/next.js` pin `a6d4c15991fd2f69c14eea4e8b655b596bc162bf` at `/Users/k244p/fullshield-bench/next`.

`/usr/bin/time -p`: real 97.54 s, user 96.96 s, sys 15.44 s. `--cpu-prof` was on, so this is slower than an unprofiled scan. The stored Phase 42 cold p50 in `bench/perf-baseline.json` is 71746.763708 ms and is a different run.

Scan exit code 1. JSON stdout was 226259 bytes and parsed to 335 findings. That count is unreviewed and is not a precision or recall number.

Self time is the sum of V8 `timeDeltas` for samples whose call frame has the same function name, url, and line. Grouped across stack positions. Total self time in the profile: 96994.3 ms.

| self ms | share | function | location |
|---|---|---|---|
| 19271.7 | 19.87% | (idle) | — |
| 16992.6 | 17.52% | inner | dist/cli/index.js:5691 (`walkScope` in the SAST taint walk) |
| 13931.0 | 14.36% | walk | dist/cli/index.js:99 (AST `walk`) |
| 5894.6 | 6.08% | (garbage collector) | — |
| 2426.8 | 2.50% | convertNode | typescript-estree convert.js:481 |
| 2340.7 | 2.41% | attachParents | dist/cli/index.js:115 |
| 2074.8 | 2.14% | everyMatch | dist/cli/index.js:4816 (secrets regex) |
| 1789.0 | 1.84% | createNode | typescript-estree convert.js:2266 |
| 1460.4 | 1.51% | scan | typescript.js:12794 |
| 1079.4 | 1.11% | (program) | — |
| 1055.3 | 1.09% | checkSyntaxError | typescript-estree check-syntax-errors.js:42 |
| 1045.4 | 1.08% | frameworksEnabled | dist/cli/index.js:184 |
| 737.0 | 0.76% | skipTrivia | typescript.js:11781 |
| 703.0 | 0.72% | (anonymous) | dist/cli/index.js:8486 |
| 693.9 | 0.72% | converter | typescript-estree convert.js:334 |
| 568.2 | 0.59% | getRange | typescript-estree node-utils.js:260 |
| 481.8 | 0.50% | checkModifiers | typescript-estree check-modifiers.js:130 |
| 452.1 | 0.47% | find | typescript-estree node-utils.js:322 |
| 440.5 | 0.45% | analyzeScope | dist/cli/index.js:5737 |
| 361.2 | 0.37% | mcpCfgEnabled | dist/cli/index.js:190 |

Later steps name the row they target:

- Step 2 (skip non-source) targets `walk`, `convertNode`, `createNode`, and `scan` by not parsing `.d.ts`, `.map`, `dist/`, `build/`, `.next/`, `coverage/`, `out/`, files over `scan.maxFileBytes`, and minified files.
- Step 3 (parse once) targets `convertNode` / `createNode` so each file is parsed at most once.
- Step 4 (module parallelism) does not remove `walk` self time; it overlaps deps, secrets, and config with SAST.
- Step 5 (call-graph cache) targets repeated reachability walks on a warm scan.
- Step 6 (lazy taint) targets `inner` / `walkScope` for files with no path to a source.
