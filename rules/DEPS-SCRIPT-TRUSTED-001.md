# DEPS-SCRIPT-TRUSTED-001

**Trusted dependency still has a dangerous lifecycle script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRUSTED=1`). CWE-829. Severity medium.

The package name is in root `trustedDependencies` and its cached lifecycle script matches the curl, outside-write, lockfile, git, token, or publish patterns. The trust list does not clear those ids. This row is additional. `node scripts/build.js` is not this finding.

## Remediation

Remove the name from `trustedDependencies` until the script is safe.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 201.
