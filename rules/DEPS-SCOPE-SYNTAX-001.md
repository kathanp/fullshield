# DEPS-SCOPE-SYNTAX-001

**Dependency name starts with @ but is not @scope/name.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_SYNTAX=1`). CWE-20. Severity high.

The name does not match `@[a-z0-9-~][a-z0-9-._~]*/[a-z0-9-~][a-z0-9-._~]*`. A well-formed `@scope/name` is not a finding. This catches a missing slash and a second slash.

## Remediation

Use a scoped name of the form @scope/name, with a single slash.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 216.
