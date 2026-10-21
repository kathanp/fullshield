# CONFIG-ELECTRON-002

**shell.openExternal without an https scheme check.** Experimental (`FULLSHIELD_EXPERIMENTAL_ELECTRON=1`). CWE-939. Severity high.

A non-literal argument to `shell.openExternal` with no `https:` check in the file. A string literal is not a finding.

## Remediation

Allow only `https:` URLs before calling `shell.openExternal`.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 102.
