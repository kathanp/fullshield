# FullShield features (2.2.0)

Inventory of what 2.2.0 does. Everything 2.1.0 already ships stays. Default `scan --json` **findings** stay byte-identical to 2.1.0 on vulnerable-app, clean-app, and every bench app (same `(ruleId, file, line, severity)` multiset after sort). No new rule id. No stable rule id is removed. No stable finding field is removed. This version does not contact a registry during the scan, does not open outbound network for performance work, does not execute scanned code, and does not rewrite the lockfile for the parked vitest/vite advisories (phase 530).

2.2.0 is a **minor**: it changes how the default engine schedules parse and module work, and it extends `FULLSHIELD_EXPERIMENTAL_PERF2`. The aim is cold and warm scan wall time, not new detections. Accuracy is never traded for speed. If a step cannot stay byte-identical, that step is parked (S3) and the rest still ships. Numbers in this file are targets and measurement rules, not claimed results; a new stored run updates `bench/perf-v2.json` and Section 28 only from that run.

`clean-app` stays at 0 high/critical findings. A `--repo` run uses local fixtures and does not park.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (2.2.0)

### Default engine (no new flag)

- **Shared AST on every scan** — the default engine parses each selected source file at most once per scan and reuses that tree for SAST (and any other module that already reads the shared cache). A counter test proves “at most once.” Finding keys stay identical to 2.1.0. This targets the profile rows for `convertNode` / `createNode` / duplicate parse work (`bench/perf-v2-profile.md`).
- **Module-level parallelism on every scan** — `deps`, `secrets`, `config`, and `sast` run concurrently; results merge in a fixed module order then the existing finding sort. Finding keys stay identical to 2.1.0. This overlaps non-SAST work with SAST instead of running modules strictly in series.
- **Lazy taint on every scan** — interprocedural taint walks only files that contain a recognized source or are on an import path (depth ≤ 5) from such a file. Finding keys stay identical to 2.1.0. This targets the profile rows for `walkScope` / `inner` on files with no path to a source.
- **File skipping stays off by default** — skipping `.d.ts`, `.map`, `dist/`, `build/`, `.next/`, `coverage/`, `out/`, oversize, and minified files remains behind `FULLSHIELD_EXPERIMENTAL_PERF2` only. Default scan still visits the same file set as 2.1.0 (aside from existing ignore rules). `meta.skipped` appears only with that flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_PERF2`)

- **Worker parse pool** — with the flag on, TypeScript-estree parse work runs in a `worker_threads` pool sized to `max(1, CPUs − 1)` (overridable by `FULLSHIELD_PARSE_WORKERS` as a positive integer cap). Output findings stay byte-identical to the same flag with `FULLSHIELD_PARSE_WORKERS=1`. A pool error falls back to in-process parse for that file and does not crash the scan. Targets parse self-time on large trees.
- **Persistent parse cache** — with the flag on, a successful parse may be reused from a local cache under the FullShield cache directory, keyed by file content hash, FullShield version, and parser options. A corrupt or foreign entry is discarded. The cache is never uploaded and never contacted over the network. Warm scans on an unchanged tree must stay finding-identical to a cold scan with the flag on. Cache misses parse normally.

### Measurement (required, not a scanner)

- After the engine work, run the existing Phase 42 / Phase 78 harness on the same machine class documented for `bench/perf-baseline.json` / `bench/perf-v2.json`, store the new timings, and update Known Limitations only if a target is still unmet. Do not invent a Next.js or nest/undici number in docs before that stored run. Do not weaken tests, thresholds, or ground truth to claim a win.

### Out of scope

- No new SAST rule ids. No vitest 5 lockfile rewrite. No republish of 2.1.0 as part of this inventory (that is a separate Publish re-run). No change to `expected-findings.json` or bench ground truth.
