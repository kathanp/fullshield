# DEPS-LOCKVER-001

**Unsupported npm lockfileVersion.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_LOCKVER=1`). CWE-1104. Severity medium.

lockfileVersion is missing, 1, or greater than 3. Versions 2 and 3 are accepted. A version 1 file is still read with the dependencies-tree parser.

## Remediation

Regenerate the lockfile with a current npm so lockfileVersion is 2 or 3.

See `SECURITY_SCANNER_SPEC.md` phase 109.
