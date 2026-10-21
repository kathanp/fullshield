# DEPS-SELFNAME-001

**A dependency name equals the root package name and is not a workspace path.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SELFNAME=1`). CWE-694. Severity medium.

A `file:` or `workspace:` spec of the same name, and a different dependency name, are not findings.

## Remediation

Use a workspace: or file: spec for the local package, or rename the dependency.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 224.
