# DEPS-OVERRIDE-WIDE-001

**Override value has no upper bound.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_WIDE=1`). CWE-829. Severity medium.

An override value is `*`, `latest`, or a `>=` / `>` range with no `<` upper bound. An exact version and a `^` range are not this finding.

## Remediation

Pin the override to an exact version or a caret range.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 134.
