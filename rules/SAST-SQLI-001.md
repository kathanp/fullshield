# SAST-SQLI-001

**Tainted input concatenated into query/execute.** CWE-89.

## Remediation

Use a parameterized query (query(sql, [params])).

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
