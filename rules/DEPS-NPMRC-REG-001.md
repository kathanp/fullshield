# DEPS-NPMRC-REG-001

**Committed .npmrc registry is not registry.npmjs.org.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_REG=1`). CWE-494. Severity high.

A committed `.npmrc` sets `registry=` or `@scope:registry=` to an `http:` or `https:` URL whose host is not `registry.npmjs.org`. That host, and a file that contains only comments, are not this finding. Token values are not printed.

## Remediation

Point registry at https://registry.npmjs.org/ or remove the line.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 137.
