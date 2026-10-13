# CONFIG-DOCKER-ENV-001

**ENV *_SECRET= or *_KEY= in the Dockerfile.** CWE-798.

## Remediation

Pass secrets at runtime, not build time.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
