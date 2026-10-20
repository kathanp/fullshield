# Quality gate (Phase 94)

`npm run quality` runs Q1–Q12 and prints `check | scope | result | count | baseline`. `npm run verify` runs it after coverage. A phase branch that fails cannot merge. Counts ratchet down only. Raising `quality/baseline.json` is a threshold change and needs a human.

Today's recorded baseline is from the Phase 94 run on `next` (2026-10-19). Existing violations were recorded, not fixed.

| Check | What it enforces | Today's number |
|---|---|---|
| Q1 | The Phase 94 ESLint rules are errors on `src` files changed versus `next` | 0 violations on `next` (no diff against itself) |
| Q2 | The same rules across all of `src`. The count for a file already in the baseline must not rise | 1512 violations across 166 files, recorded |
| Q3 | Every `eslint-disable` has `-- reason` and is listed in `docs/DECISIONS.md`. The total must not rise | 0 disables |
| Q4 | `knip` unused files, exports, and dependencies introduced by the branch. `package.json` `exports` stay public | 160 existing issues recorded |
| Q5 | `api/fullshield.api.json` matches exported `.d.ts` text, `--help`, `FS-E` codes, rule IDs, and experimental flags | snapshot committed in this phase |
| Q6 | `FS-E` codes in `src` are in `docs/errors.md`. A new bare `throw new Error` fails | 66 existing bare throws recorded; 0 undocumented codes |
| Q7 | `child_process`, `eval`, `new Function`, `vm`, dynamic `require`, and `process.binding` are in `quality/allowed-dangerous.json`. No new site is allowed in `src/runtime*`. Two existing RASP hook sites there are recorded in the baseline, not exempt | 12 allowlisted calls; 2 existing runtime sites recorded |
| Q8 | A new `http(s)://` literal outside `src/net/hosts.ts` fails. Allowed hosts there are OSV, `registry.npmjs.org`, and loopback. 34 existing literals are recorded, not yet audited. Until they are, R15 is enforced for new code only | 34 existing literals recorded (unaudited) |
| Q9 | A `src` file added versus `next` has ≥ 90% lines and ≥ 80% branches in `coverage/coverage-summary.json` | no added files when this runs on `next` |
| Q10 | A new rule ID needs a mutation that the tests kill | 70 rules already in the tree; none new versus the baseline |
| Q11 | Two default `scan --json --offline-safe` runs of vulnerable-app, and of `~/fullshield-bench/dvna` when that checkout exists, match after sorting findings and dropping `metadata.durationMs` and `metadata.startedAt` (those are the clock). The same check runs for an experimental flag that is not yet in the baseline | measured on this machine during `npm run quality` |
| Q12 | `npm pack --dry-run` matches `quality/pack-files.txt`, ships no `test/`, `bench/`, `reports/`, or `.map`, and `pack-budget` passes | 106 packed files |

`src/net/hosts.ts` is the host list for Q8. Phase 56 hosts are not on it.
