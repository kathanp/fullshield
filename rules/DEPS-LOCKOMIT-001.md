# DEPS-LOCKOMIT-001

**Manifest dependency omitted from the lock root.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_LOCKOMIT=1`). CWE-829. Severity high.

package.json dependencies names a package that is absent from packages[""].dependencies and from the top-level dependencies object. A name present in either place is not a finding. A range that does not contain the locked version is a different check.

## Remediation

Regenerate the lockfile so the package is a root dependency entry.

See `SECURITY_SCANNER_SPEC.md` phase 126.
