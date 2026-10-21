# DEPS-NAME-ENCODED-001

**Dependency name contains a percent sign.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NAME_ENCODED=1`). CWE-20. Severity high.

A name without `%` is not a finding.

## Remediation

Depend on the package by its registry name, without percent-encoding.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 222.
