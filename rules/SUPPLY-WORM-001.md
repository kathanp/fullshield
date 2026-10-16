# SUPPLY-WORM-001

**Self-replicating worm indicators in dependency code (static).** CWE-506.

Experimental (`FULLSHIELD_EXPERIMENTAL_VEX=1`). Flags package sources that read npm/GitHub tokens (`~/.npmrc`, `NPM_TOKEN`, `GITHUB_TOKEN`) **and** `npm publish`, a registry PUT, GitHub API repo/workflow creation, or writing `.github/workflows/*`. Critical. Never executes packages.

## Remediation

Do not install the package. Remove it from the lockfile, delete `node_modules`, reinstall, and rotate npm/GitHub tokens on machines that installed it.
