# DEPS-SEPARATOR-001

**Direct dependency swaps separators in a popular package name.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SEPARATOR=1`). CWE-494. Severity medium.

Treating `.`, `-`, and `_` as the same character, the direct name equals a popular package and the strings differ. The exact popular name, a one-letter difference, and a twin at Levenshtein distance 1 are not findings.

## Remediation

Confirm you intended this name rather than the popular package.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 212.
