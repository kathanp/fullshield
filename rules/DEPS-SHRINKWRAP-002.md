# DEPS-SHRINKWRAP-002

**Shrinkwrap and package-lock name@version sets differ.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP=1`). CWE-436. Severity high.

Both npm-shrinkwrap.json and package-lock.json exist and the package name@version sets from the package-lock parser are not the same.

## Remediation

Delete one of the files, or regenerate both from the same install so the sets match.

See `SECURITY_SCANNER_SPEC.md` phase 108.
