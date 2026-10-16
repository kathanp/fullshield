# SAST-GQL-001

**GraphQL introspection enabled in production, no depth/complexity limit, or tainted resolver args reaching sinks.** CWE-770 / CWE-200.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Disable introspection in production. Add `graphql-depth-limit` (or query complexity). Validate resolver arguments before they reach SQL/shell/eval.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
