# SECRET-AWS-001

**AWS access key.** CWE-798.

## Placeholder

`FULLSHIELD_EXPERIMENTAL_SECRET_CHECK` treats the documented example access key ID `AKIAIOSFODNN7EXAMPLE` as a placeholder. Confidence is lowered. The finding stays, and severity is unchanged.

https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html

## Remediation

Rotate the key. Load it from the environment. Removing it from the file is not enough — it stays in git history.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
