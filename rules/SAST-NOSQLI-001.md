# SAST-NOSQLI-001

**req.body/req.query passed as a Mongo filter, or a tainted `$where` string.** CWE-943.

## Remediation

Build an allow-listed filter object; never pass the request object through.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
