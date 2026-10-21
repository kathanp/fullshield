# DEPS-TARBALL-TOPLEVEL-001

**Package entry calls the network or child_process outside a function.** High. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_TOPLEVEL=1`). CWE-829.

Direct production dependency only. `main` or an `exports` file contains `fetch(`, `http.request`, `https.request`, or a `child_process` call that is not inside a function. The file is parsed with the existing parser. A file that does not parse emits nothing. The same call inside a function is not this finding.

## Remediation

Move the call inside a function.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 184.
