# Decisions

## ESLint disables

Phase 94 recorded 0 `eslint-disable` comments in `src/`. A new one needs `-- reason` on the same line and a row in this file naming the path.

## Autopilot decisions

D-1 | phase-501 | Diff scan uses one import hop, `FS-E018`, and the existing rule ids for a request value returned from a changed file | The features file limits the frontier to the changed file, its relative-literal importers, and its relative-literal imports. Hop 2 would read more of the repo than that file allows. `FS-E018` is the next CLI code. It is matched before `FS-E006` because the flag name contains that prefix. | APPROVED

D-2 | phase-502 | A stored field and a closed-over name each cross one boundary | The features file's examples are `obj.a` and one nested function. Depth 2 stays silent so the negative fixture is the closest miss. `JSON.parse` stays tainted because it is not a sanitizer. | APPROVED

D-3 | phase-503 | Field and closure taint is the default scan | The approved features file promotes phase 502. The flag stays accepted and does not turn the behavior off. On 2026-10-24 the human delegated the R3 edit of the two unset-flag assertions in `phase502-flow2.test.ts`. | APPROVED

D-4 | phase-504 | ORM raw queries and the named shell variants are the default scan | The approved features file promotes those phase 27 sinks. The flag stays accepted and does not turn them off. The same delegated R3 edit covers the two flag-off assertions in `coverage-gaps.test.ts`. Bindings and `execFile` stay silent. | APPROVED

D-5 | phase-505 | LDAP findings require an ldap import or an ldap receiver | A bare `bind` of request data is common and would light up `clean-app`. The import specifier or the receiver identifier must contain `ldap`. CWE-90. | APPROVED

D-6 | phase-506 | Reflected CORS is the request Origin header plus credentials on that response | A fixed origin, including `clean-app`'s allow-list, stays silent. `origin: '*'` stays `CONFIG-CORS-001`. CWE-942. | APPROVED
