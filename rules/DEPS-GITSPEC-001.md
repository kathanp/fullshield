# DEPS-GITSPEC-001

**Git protocol in a direct package.json spec.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_GITSPEC=1`). CWE-829. Severity high.

A direct spec uses `git:`, `git+https:`, `git+ssh:`, `git+http:`, `github:`, `gitlab:`, `bitbucket:`, or `gist:`. A semver range is not this finding. When the lockfile `resolved` URL is also git, this id is the one emitted for that spec.

## Remediation

Replace the git spec with a registry version that has a lockfile integrity. Do not clone the git URL.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 129.
