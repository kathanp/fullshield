# DEPS-SHRINKWRAP-001

**npm-shrinkwrap.json is the only lockfile.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP=1`). CWE-829. Severity info.

npm-shrinkwrap.json is present and no other lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock) is at the repo root. The file is parsed with the package-lock parser.

## Remediation

Commit one lockfile. Prefer package-lock.json unless the project intentionally publishes a shrinkwrap.

See `SECURITY_SCANNER_SPEC.md` phase 108.
