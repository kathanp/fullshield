# DEPS-ROOTVER-001

**Root package version differs from the lockfile.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_ROOTVER=1`). CWE-436. Severity medium.

packages[""].version is a string and it differs from package.json version. A missing root entry is not a finding. Workspace package versions are not compared.

## Remediation

Regenerate the lockfile so the root version matches package.json.

See `SECURITY_SCANNER_SPEC.md` phase 111.
