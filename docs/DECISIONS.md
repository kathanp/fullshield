# Decisions

## ESLint disables

Phase 94 recorded 0 `eslint-disable` comments in `src/`. A new one needs `-- reason` on the same line and a row in this file naming the path.

## Autopilot decisions

D-1 | phase-501 | Diff scan uses one import hop, `FS-E018`, and the existing rule ids for a request value returned from a changed file | The features file limits the frontier to the changed file, its relative-literal importers, and its relative-literal imports. Hop 2 would read more of the repo than that file allows. `FS-E018` is the next CLI code. It is matched before `FS-E006` because the flag name contains that prefix. | APPROVED

D-2 | phase-502 | A stored field and a closed-over name each cross one boundary | The features file's examples are `obj.a` and one nested function. Depth 2 stays silent so the negative fixture is the closest miss. `JSON.parse` stays tainted because it is not a sanitizer. | APPROVED
