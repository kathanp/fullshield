# DEPS-SCRIPT-GIT-001

**Lifecycle script invokes git.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_GIT=1`). CWE-829. Severity high.

A cached lifecycle script contains `git ` or `.git/hooks`. The word `digital` is not this finding. The script is not executed and git is not invoked.

## Remediation

Do not install a package whose install script runs git or writes hooks.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 198.
