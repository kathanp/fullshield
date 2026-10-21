# DEPS-URLSPEC-001

**HTTP(S) dependency URL outside the npm registry.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_URLSPEC=1`). CWE-494. Severity high.

A direct spec is an `http:` or `https:` URL whose host is not `registry.npmjs.org`. A semver range and a `https://registry.npmjs.org/` tarball are not this finding.

## Remediation

Use a registry.npmjs.org tarball or a semver range.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 131.
