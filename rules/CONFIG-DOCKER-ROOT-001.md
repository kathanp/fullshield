# CONFIG-DOCKER-ROOT-001

**Dockerfile has no USER instruction.** CWE-250.

## Remediation

Add USER node (or another non-root user).

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
