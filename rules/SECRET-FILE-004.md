# SECRET-FILE-004

**kubeconfig credential.** Experimental (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). CWE-798.

A file with `apiVersion: v1` and `kind: Config` that also has a `token:` or `client-key-data:` value.

## Remediation

Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is not enough: it remains visible in git history.

See `SECURITY_SCANNER_SPEC.md` §7.2 and Section 46 phase 105.
