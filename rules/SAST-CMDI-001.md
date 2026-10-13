# SAST-CMDI-001

**Tainted input reaching exec/execSync/spawn({shell:true}).** CWE-78.

## Remediation

Use execFile with an argument array and validate input.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
