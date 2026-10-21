# DEPS-NPMRC-SCRIPT-001

**Committed .npmrc sets ignore-scripts=false.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_SCRIPT=1`). CWE-829. Severity info.

A committed `.npmrc` sets `ignore-scripts=false`. `ignore-scripts=true`, and a file with no such key, are not this finding. This is informational. It does not mean the project is compromised.

## Remediation

Set ignore-scripts=true and list the installers you accept in trustedDependencies.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 138.
