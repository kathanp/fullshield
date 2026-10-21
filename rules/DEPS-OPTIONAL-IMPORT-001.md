# DEPS-OPTIONAL-IMPORT-001

**Optional dependency imported outside try/catch.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_OPTIONAL=1`). CWE-703. Severity low.

Production code imports a package the lock marks optional: true and the import is not inside a try/catch. An import inside try/catch, or a package that is not optional, is not a finding. This does not change an advisory on that package.

## Remediation

Import the package inside try/catch, or make the dependency required.

See `SECURITY_SCANNER_SPEC.md` phase 124.
