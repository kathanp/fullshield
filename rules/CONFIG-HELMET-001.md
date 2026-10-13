# CONFIG-HELMET-001

**express() app never calls helmet().** CWE-693.

## Remediation

app.use(helmet()). Router-only files are not flagged.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
