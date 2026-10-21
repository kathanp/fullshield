# DEPS-GITDEP-001

**Git dependency.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_GITDEP=1`). CWE-829. Severity high.

A spec or resolved value uses git:, git+https:, git+ssh:, git+http:, github:, gitlab:, bitbucket:, or gist:. The URL is not cloned. A registry tarball is not a finding.

## Remediation

Depend on a registry release with an integrity hash.

See `SECURITY_SCANNER_SPEC.md` phase 120.
