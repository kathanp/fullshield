# Node 20

Checked against the source tree on 2026-10-16. This is a compatibility note, not a claim that the CI matrix has already gone green.

## APIs that need Node 22.13

| API | Where | On Node 20 |
|---|---|---|
| `node:sqlite` (`DatabaseSync`) | `src/dashboard/index.ts` history storage used by `report --serve` | `openHistory` throws `history requires Node 22.13+` |
| `node:sqlite` | `src/runtime/rasp/hooks.ts` optional wrap when the app loads `node:sqlite` | The wrap is in try/catch and no-ops. Node 20 cannot load that module anyway. |
| `node:sqlite` | tests that seed a real SQLite sink | Those tests skip when `require('node:sqlite')` throws. |

`src/confirm/index.ts` does not import `node:sqlite`. The confirm command keeps working on Node 20. Confirm tests that seed a SQLite sink skip.

`src/modules/secrets/history.ts` (`scan --history`) reads git. It does not use `node:sqlite`.

## Other Node APIs in this repo

| API | Minimum | Used by |
|---|---|---|
| `import.meta.dirname` | 20.11 / 21.2 | `eslint.config.js` only. Not in the published scanner. |
| `os.availableParallelism` | 18.14 | parse pool size |
| `node:worker_threads` `resourceLimits.maxOldGenerationSizeMb` | 16 | parse pool |

No `fs.glob`, `util.styleText`, `URL.parse`, or `Promise.withResolvers` in `src/`.

## What still needs a human

- This machine has Node 16, 18, and 24. Node 20 was not executed here.
- CI lists Node 20, 22, and 24. Branch protection that requires the old six job names has to be updated after the new Node 20 jobs report once. That is a GitHub setting, not a code change.
- RASP tests that need `node:sqlite` do not run on Node 20. Shell, path, and corpus tests still run.
