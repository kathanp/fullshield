# SECRET-FILE-007

**Committed private key file.** Experimental (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). CWE-321.

`id_rsa`, `id_ed25519`, `*.p12`, `*.pfx`, or `*.keystore`. A `.pub` file is not a finding. A PEM private key may also match `SECRET-PRIVKEY-001`.

## Remediation

Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is not enough: it remains visible in git history.

See `SECURITY_SCANNER_SPEC.md` §7.2 and Section 46 phase 105.
