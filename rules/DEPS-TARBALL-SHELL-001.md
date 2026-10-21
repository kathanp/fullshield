# DEPS-TARBALL-SHELL-001

**Lifecycle script invokes a shell or downloader.** High. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_SHELL=1`). CWE-78.

Direct production dependency only. A `preinstall`, `install`, or `postinstall` string contains `curl`, `wget`, `bash`, `sh -c`, `powershell`, or `child_process`.

## Remediation

Remove those tokens from the install script.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 172.
