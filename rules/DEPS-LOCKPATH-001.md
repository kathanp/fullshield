# DEPS-LOCKPATH-001

**Lockfile packages key has an unexpected shape.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_LOCKPATH=1`). CWE-22. Severity high.

A packages key is not "" and does not start with node_modules/. A key that contains .. is the same id. node_modules/foo and node_modules/foo/node_modules/bar are not findings.

## Remediation

Regenerate the lockfile so every packages key is "" or a node_modules path with no .. segment.

See `SECURITY_SCANNER_SPEC.md` phase 125.
