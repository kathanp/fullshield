# DEPS-PACKAGEMANAGER-001

**packageManager is missing while a lockfile exists.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_PACKAGEMANAGER=1`). CWE-1104. Severity low.

`package.json` has no `packageManager` field and a lockfile is present (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, or `bun.lock`).

Narrowed for R12: a package with `"private": true` whose every direct dependency spec is a caret range (`^MAJOR.MINOR.PATCH`) is not this finding. A public package, a private package with no direct specs, and a private package with any non-caret direct spec still match when the field is missing and a lockfile exists.

## Remediation

Set packageManager to the lockfile manager at an exact version, for example npm@10.9.2.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 140.
