# DEPS-SCRIPT-MISMATCH-001

**Install-script flag disagrees with scripts.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_MISMATCH=1`). CWE-829. Severity medium.

The lock sets `hasInstallScript` and the cached `scripts` object has none of `preinstall`, `install`, or `postinstall`. A present key is not this finding. No tarball cache means no finding.

## Remediation

Refresh the cached package manifest before trusting the lock bit.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 202.
