# DEPS-NONSEMVER-001

**Locked version is not semver.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NONSEMVER=1`). CWE-1104. Severity medium.

A locked version is not MAJOR.MINOR.PATCH with an optional prerelease. Git shas, file: specs, *, and empty versions match. The locked text is not rewritten for an advisory lookup.

## Remediation

Lock a MAJOR.MINOR.PATCH release from the registry.

See `SECURITY_SCANNER_SPEC.md` phase 112.
