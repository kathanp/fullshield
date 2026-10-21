# DEPS-TARBALL-SKIP-001

**Direct production tarball refused because integrity is missing.** Info. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_GATE=1`). CWE-353.

One row per direct production dependency that has an `https://registry.npmjs.org` tarball URL and no lock integrity. The tarball is not read. Transitive packages are not downloaded and do not produce this row. A dependency with no tarball URL is not this finding. When every direct production dependency has integrity, no row is emitted.

## Remediation

Add a sha512 integrity to the lock entry before fetching its tarball.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 187.
