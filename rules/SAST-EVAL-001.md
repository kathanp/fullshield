# SAST-EVAL-001

**eval, new Function, vm.runInNewContext, or lib.eval of a non-literal.** CWE-95.

## Remediation

Do not evaluate user input. Use a parser or allow-list.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
