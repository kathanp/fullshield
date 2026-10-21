# DEPS-SCOPE-TYPO-001

**Direct dependency scope is one edit from a popular scope.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_TYPO=1`). CWE-494. Severity medium.

A direct `@scope/name` dependency whose scope is Levenshtein distance 1 from a scope on the popular-package list, and whose basename is a popular package in that real scope. The real scope, a distance-1 scope whose basename is not on that list, and unscoped names are not findings.

## Remediation

Depend on the popular scoped package if that is the one you meant.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 208.
