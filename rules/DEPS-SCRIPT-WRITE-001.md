# DEPS-SCRIPT-WRITE-001

**Lifecycle script writes outside the package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_WRITE=1`). CWE-22. Severity high.

A cached lifecycle script writes a path that starts with `..`, `/`, `~/`, or an expansion of `HOME` or `USERPROFILE`. A relative path such as `lib/out.js` is not this finding. The script is not executed.

## Remediation

Do not install the package until the write stays inside the package directory.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 196.
