# DEPS-REG-INSTALLSCRIPT-001

**Packument lists an install script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_INSTALLSCRIPT=1`). CWE-829. Severity info.

hasInstallScript is true or the version scripts include preinstall, install, or postinstall. One row per package version. Script bodies are out of scope. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 160.
