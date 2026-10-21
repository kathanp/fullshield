# DEPS-DEV-PROD-EDGE-001

**Dev package is required by production.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_DEVPROD=1`). CWE-829. Severity medium.

A package marked dev: true is also required by a package that is not dev: true. A dev-only package, and a production package that does not require a dev package, are not findings. This is the edge, not a second advisory.

## Remediation

Move the package out of the production graph, or stop marking it dev.

See `SECURITY_SCANNER_SPEC.md` phase 127.
