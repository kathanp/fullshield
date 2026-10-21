# DEPS-TYPES-001

**Project depends on both foo and @types/foo when foo already ships types.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TYPES=1`). CWE-1104. Severity info.

foo's packument has a non-empty `types` or `typings` field. Neither field, and a missing packument, are not findings.

## Remediation

Remove the @types package if the package's own types are the ones TypeScript should use.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 217.
