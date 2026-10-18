# Node 20

Node 20 reached end of life in April 2026. The package enforces Node >= 22.13 in `package.json` `engines`, in `doctor`, and in CI (Node 22 and 24). The published 0.3.0 tarball still says `engines` `>=20.11`. This tree keeps the Phase 46 floor. History storage may still say it needs `node:sqlite`. That API is inside the floor.

Checked against the source tree on 2026-10-16. This is a compatibility note.

## APIs that need Node 22.13

| API | Where | On Node 20 |
|---|---|---|
| `node:sqlite` (`DatabaseSync`) | `src/dashboard/index.ts` history storage used by `report --serve` | `openHistory` throws `history requires Node 22.13+` |
| `node:sqlite` | `src/runtime/rasp/hooks.ts` optional wrap when the app loads `node:sqlite` | The wrap is in try/catch and no-ops. Node 20 cannot load that module anyway. |
| `node:sqlite` | tests that seed a real SQLite sink | Those tests skip when `require('node:sqlite')` throws. |

`src/confirm/index.ts` does not import `node:sqlite`. `src/modules/secrets/history.ts` (`scan --history`) reads git. It does not use `node:sqlite`.

## Other Node APIs in this repo

| API | Minimum | Used by |
|---|---|---|
| `import.meta.dirname` | 20.11 / 21.2 | `eslint.config.js` only. Not in the published scanner. |
| `os.availableParallelism` | 18.14 | parse pool size |
| `node:worker_threads` `resourceLimits.maxOldGenerationSizeMb` | 16 | parse pool |

No `fs.glob`, `util.styleText`, `URL.parse`, or `Promise.withResolvers` in `src/`.

## What still needs a human

CI lists Node 22 and 24. Branch protection that still requires old Node 20 job names has to be updated by a human after the Node 22 and 24 jobs have reported once. That is a GitHub setting. This change does not edit it.
