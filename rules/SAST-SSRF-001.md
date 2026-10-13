# SAST-SSRF-001

**Tainted URL into fetch/axios/http/needle/got/request/superagent/undici.** CWE-918.

## Remediation

Allow-list destinations; do not fetch user-supplied URLs.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
