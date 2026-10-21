# SECRET-FILE-002

**npm credential in `.npmrc`.** Experimental (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). CWE-798.

A literal `_authToken=` or `_auth=` value. `${...}` interpolation is not a finding.

## Remediation

Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is not enough: it remains visible in git history.

See `SECURITY_SCANNER_SPEC.md` §7.2 and Section 46 phase 105.
