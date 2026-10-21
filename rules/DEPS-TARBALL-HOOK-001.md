# DEPS-TARBALL-HOOK-001

**Tarball contains a git hook or GitHub workflow.** Critical. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HOOK=1`). CWE-829.

Direct production dependency only. An archived path includes `.git/hooks/` or `.github/workflows/`. A README that only mentions those words is not this finding. Distinct from `SUPPLY-WORKFLOW-001`, which is source that writes those paths.

## Remediation

Do not install this package.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 177.
