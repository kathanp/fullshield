# DEPS-RESOLVED-HTTP-001

**Tarball URL uses cleartext http.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HTTP=1`). CWE-319. Severity high.

resolved uses the http: protocol. https://registry.npmjs.org is not a finding. A git+ssh: URL is not this rule.

## Remediation

Use an https://registry.npmjs.org tarball URL.

See `SECURITY_SCANNER_SPEC.md` phase 115.
