# SECRET-FILE-005

**Committed Terraform state.** Experimental (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). CWE-312. Severity high.

Any `*.tfstate` or `*.tfstate.backup` file. State holds secrets.

## Remediation

Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is not enough: it remains visible in git history.

See `SECURITY_SCANNER_SPEC.md` §7.2 and Section 46 phase 105.
