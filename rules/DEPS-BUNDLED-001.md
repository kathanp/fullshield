# DEPS-BUNDLED-001

**Bundled package is not named by the root bundle list.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_BUNDLED=1`). CWE-829. Severity medium.

A lock entry has inBundle: true or bundled: true and the root bundleDependencies / bundledDependencies array does not name that package. The package is not skipped.

## Remediation

Add the package to bundleDependencies, or remove the bundled flag.

See `SECURITY_SCANNER_SPEC.md` phase 122.
