# DEPS-TARBALL-OBFUSC-001

**Lifecycle script passes a long base64 literal to eval, Function, or spawn.** High. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_OBFUSC=1`). CWE-506.

Direct production dependency only. The literal is at least 32 characters and sits inside the call. A shorter literal, or a long literal that is only assigned, is not this finding. This id is the tarball lifecycle script, distinct from `SUPPLY-OBFUSCATE-001`.

## Remediation

Do not install this package.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 174.
