# DEPS-TARBALL-BIN-001

**package.json bin target is missing from the tarball.** Medium. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_BIN=1`). CWE-427.

Direct production dependency only. The path is inside the package and is not a file in the archive. A path with `..` or an absolute path is `DEPS-TARBALL-PATH-001` only.

## Remediation

Point bin at a file that exists inside the package, or remove the bin entry.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 175.
