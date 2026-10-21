# DEPS-TARBALL-ID-001

**Tarball package.json name or version differs from the lock.** Critical. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_ID=1`). CWE-494.

Direct production dependency only. Compared against `package/package.json` in the cached tarball. A missing manifest is not this finding.

## Remediation

Do not install the archive. The packed name and version must match the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 169.
