# DEPS-SCRIPT-COND-001

**Lifecycle script hides behavior behind CI or NODE_ENV.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_COND=1`). CWE-829. Severity medium.

A cached lifecycle script branches with a brace `if` on `process.env.CI` or `NODE_ENV` compared with `production`, and the non-CI or production branch contains a phase 193–200 script pattern. A branch that only changes a log string is not this finding. An unconditional pattern stays on the earlier phase and this id does not also fire for that pattern.

## Remediation

Read the non-CI and production branches before installing.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 206.
