# DEPS-MULTLOCK-001

**Multiple lockfiles at the repo root.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_MULTLOCK=1`). CWE-436. Severity medium.

Two or more of package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, and bun.lock exist at the repo root. The message names the files. No winner is chosen.

## Remediation

Keep a single lockfile.

See `SECURITY_SCANNER_SPEC.md` phase 110.
