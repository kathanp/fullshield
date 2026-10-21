# DEPS-PACKAGEMANAGER-002

**packageManager is not name@exact or does not match the lockfile.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_PACKAGEMANAGER=1`). CWE-1104. Severity medium.

`packageManager` is present and is not `<name>@<exact semver>` for `npm`, `pnpm`, `yarn`, or `bun`, or the name does not match the lockfile that is present (`package-lock.json` and `npm-shrinkwrap.json` are `npm`, `yarn.lock` is `yarn`, `pnpm-lock.yaml` is `pnpm`, `bun.lock` is `bun`). `npm@10.9.2` next to `package-lock.json` is not this finding. A `+sha512.` suffix does not by itself make the field invalid.

## Remediation

Set packageManager to the lockfile manager at an exact version, such as npm@10.9.2.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 140.
