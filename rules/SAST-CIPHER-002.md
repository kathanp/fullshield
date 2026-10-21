# SAST-CIPHER-002

**Hardcoded symmetric key.** Experimental (`FULLSHIELD_EXPERIMENTAL_CRYPTO2=1`). CWE-321. Severity high.

A string literal passed as the key to `createCipheriv` or `createHmac`. A key read from `process.env` is not a finding. This rule does not add a second finding on a line already reported as `SECRET-JWT-*` or `SECRET-ENTROPY-001`.

## Remediation

Load the key from an environment variable or a secret manager.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 96.
