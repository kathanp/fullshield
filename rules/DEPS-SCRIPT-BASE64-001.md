# DEPS-SCRIPT-BASE64-001

**Lifecycle script decodes base64 into eval.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_BASE64=1`). CWE-95. Severity high.

Same condition as phase 174, applied to cached lifecycle script text: a base64 literal of 32 or more characters passed to `eval`, `Function`, or `spawn`. A shorter literal, or a long literal that is only assigned, is not this finding. If the cache file sets `tarballObfuscReported`, phase 174 already reported the package and this id is skipped.

## Remediation

Do not install the package. Treat decode-and-eval in an install script as malicious.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 194.
