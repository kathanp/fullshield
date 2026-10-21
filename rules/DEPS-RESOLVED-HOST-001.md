# DEPS-RESOLVED-HOST-001

**Tarball host is not the npm registry.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HOST=1`). CWE-494. Severity high.

resolved is an https URL whose host is not registry.npmjs.org. An http: URL is left to the cleartext rule.

## Remediation

Resolve the package from https://registry.npmjs.org.

See `SECURITY_SCANNER_SPEC.md` phase 114.
