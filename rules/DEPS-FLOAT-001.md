# DEPS-FLOAT-001

**Floating direct dependency spec.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_FLOAT=1`). CWE-829. Severity medium.

A direct dependency spec is `*`, `x`, `X`, `latest`, or empty.

## Remediation

Pin a semver range with an upper bound, or an exact version.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 128.
