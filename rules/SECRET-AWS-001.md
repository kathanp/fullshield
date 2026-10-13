# SECRET-AWS-001

**AWS access key.** CWE-798.

## Remediation

Rotate the key. Load it from the environment. Removing it from the file is not enough — it stays in git history.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
