# SECRET-NEXTPUB-001

**Public env name looks like a secret.** Experimental (`FULLSHIELD_EXPERIMENTAL_NEXT=1`). CWE-798. Severity high.

A `NEXT_PUBLIC_` name contains `SECRET`, `PRIVATE`, or `KEY`, unless the name contains `PUBLISHABLE`.

## Remediation

Rename the variable so the secret is not shipped to the client.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 103.
