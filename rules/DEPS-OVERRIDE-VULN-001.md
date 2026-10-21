# DEPS-OVERRIDE-VULN-001

**Override pins a version the OSV cache marks affected.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_VULN=1`). CWE-1104. Severity high.

`overrides`, `resolutions`, or `pnpm.overrides` pins one exact version, and `{cache}/osv/<name>@<version>.json` lists at least one advisory. The message cites that OSV id. A missing cache file, or a file whose `vulns` array is empty, is not a finding. This check does not invent an advisory and does not contact the network.

## Remediation

Pin a version that the OSV cache does not list as affected.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 133.
