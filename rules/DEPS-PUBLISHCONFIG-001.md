# DEPS-PUBLISHCONFIG-001

**publishConfig.registry is not the npm registry.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_PUBLISHCONFIG=1`). CWE-494. Severity high.

`private` is not `true` and `publishConfig.registry` is an `http:` or `https:` URL whose host is not `registry.npmjs.org`. A public package whose publishConfig registry is the npm registry is not this finding.

## Remediation

Publish to registry.npmjs.org, or set private to true.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 145.
