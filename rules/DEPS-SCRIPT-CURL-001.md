# DEPS-SCRIPT-CURL-001

**Lifecycle script pipes a download to a shell.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_CURL=1`). CWE-494. Severity critical.

A cached lifecycle script contains `curl` or `wget` and a pipe to `sh`, `bash`, or `node`. A download written to a file with no pipe is not this finding. Fixture hosts are `example.invalid`. The script is not executed.

## Remediation

Do not install the package. A download piped to a shell is remote code execution.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 193.
