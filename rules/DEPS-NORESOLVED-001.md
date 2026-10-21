# DEPS-NORESOLVED-001

**Semver packages entry has no resolved URL.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NORESOLVED=1`). CWE-829. Severity medium.

A packages entry has a semver version and no resolved URL. The root "" entry and link: workspace rows are excluded. A row whose only fields are version, name, and license is not an install record and is excluded.

## Remediation

Regenerate the lockfile so the package has a resolved tarball URL.

See `SECURITY_SCANNER_SPEC.md` phase 113.
