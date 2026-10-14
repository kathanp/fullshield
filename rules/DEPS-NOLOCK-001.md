# DEPS-NOLOCK-001

**package.json is present but no lockfile.** Info.

Transitive versions cannot be audited. Exact versions pinned in `package.json` (no `^`/`~` range) are still queried against OSV.

## Remediation

Commit `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`.
