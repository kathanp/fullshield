# DEPS-SCRIPT-LOCK-001

**Lifecycle script writes the lockfile.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_LOCK=1`). CWE-506. Severity high.

A cached lifecycle script contains `package-lock.json` or `npm-shrinkwrap.json` next to `write`, `>`, or `fs.write`. A comment in a non-script file is not this finding. A script that does not name the lockfile is not this finding.

## Remediation

Do not install a package that rewrites the lockfile during install.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 197.
