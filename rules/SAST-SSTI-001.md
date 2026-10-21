# SAST-SSTI-001

**Server-side template injection.** Experimental (`FULLSHIELD_EXPERIMENTAL_SSTI=1`). CWE-1336. Severity critical.

A tainted value is the template source for an engine listed in `models/ssti.json`. The data argument is not this rule. An engine that is not in the pack is not a finding.

## Remediation

Render a fixed template and pass user data as data, not as template source.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 97.
