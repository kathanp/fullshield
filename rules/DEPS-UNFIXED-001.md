# DEPS-UNFIXED-001

**Production dependency with no fixed version.** Experimental (`FULLSHIELD_EXPERIMENTAL_HEALTH=1`). CWE-1104. Severity medium.

A production dependency has an OSV advisory with no `fixed` event, and the registry publish date for that version is older than 730 days. An unknown publish date is not a finding. The console shows this only when reachability is `reachable`.

## Remediation

Decide whether to keep this dependency. FullShield does not name a replacement.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 106.
