# DEPS-SCRIPT-PREPARE-001

**Dependency prepare script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PREPARE=1`). CWE-829. Severity high for a git dependency, otherwise medium.

`scripts.prepare` is a non-empty string in the cached tarball descriptor. prepare runs on local npm install for git dependencies. No prepare script means no finding. Missing cache means no finding.

## Remediation

Read the prepare script before installing. Git dependencies run it during npm install.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 191.
