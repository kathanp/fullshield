# SAST-POSTMSG-001

**postMessage without an origin check.** Experimental (`FULLSHIELD_EXPERIMENTAL_BROWSER=1`). CWE-346. Severity medium.

A `message` listener uses `event.data` and does not read `event.origin`. `postMessage` of a secret-named value with target `*` is the same rule.

## Remediation

Compare `event.origin` before using `event.data`, and pass a concrete target origin.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 101.
