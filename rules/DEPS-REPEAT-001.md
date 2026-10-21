# DEPS-REPEAT-001

**Direct dependency repeats a popular package basename.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REPEAT=1`). CWE-494. Severity medium.

The name is `foo-foo` or `@foo/foo` and `foo` is a popular package basename. The basename itself, and a name at Levenshtein distance 1 from a popular package, are not findings.

## Remediation

Confirm you intended this repeated name.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 213.
