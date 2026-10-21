# SECRET-FILE-006

**Cloud service-account key.** Experimental (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). CWE-798.

JSON with `"type": "service_account"` and a non-empty `"private_key"`.

## Remediation

Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is not enough: it remains visible in git history.

See `SECURITY_SCANNER_SPEC.md` §7.2 and Section 46 phase 105.
