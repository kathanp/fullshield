# DEPS-HOMOGLYPH-001

**Dependency name is not ASCII and matches a popular package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_HOMOGLYPH=1`). CWE-1007. Severity high.

The name's NFKC form equals a popular package, or Cyrillic/Greek lookalikes for a, e, o, p, c, x, and y normalize to one. An ASCII name, and a non-ASCII name that does not map to a popular package, are not findings.

## Remediation

Confirm the package name character by character before installing it.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 209.
