# SECRET-FILE-003

**Docker registry credential in `config.json`.** Experimental (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). CWE-798.

`config.json` (including `.docker/config.json`) that contains `auths` and a non-empty `auth` value.

## Remediation

Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is not enough: it remains visible in git history.

See `SECURITY_SCANNER_SPEC.md` §7.2 and Section 46 phase 105.
