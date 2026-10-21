# DEPS-TARBALL-DYNAMIC-001

**Top-level dynamic require or import in the package entry.** Medium. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_DYNAMIC=1`). CWE-829.

Direct production dependency only. `main` or an `exports` file contains `require(` or `import(` whose argument is not a string literal, and the call is not inside a function. A literal `require('fs')` and a call inside a function are not this finding.

## Remediation

Use a string literal, or move the call inside a function.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 186.
