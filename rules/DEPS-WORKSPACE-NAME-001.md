# DEPS-WORKSPACE-NAME-001

**A workspace package name is resolved from registry.npmjs.org.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_WORKSPACE_NAME=1`). CWE-494. Severity high.

The lock `resolved` URL host is the npm registry rather than `link:` or `file:`. A `link:` to the workspace path is not a finding.

## Remediation

Link the workspace package with link: or file: so install does not fetch a registry package of the same name.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 225.
