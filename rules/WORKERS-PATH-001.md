# WORKERS-PATH-001

**SQS record body reaches a path.** CWE-22. Requires `FULLSHIELD_EXPERIMENTAL_WORKERS=1` and `--modules workers`.

An SQS `Records` loop passes `record.body` to a file path call. An allowlist that rejects the body before the call is not this finding.

## Remediation

Reject values that are not on an allowlist before the path call. Do not pass the raw record body as a path.
