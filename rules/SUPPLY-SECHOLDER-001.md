# SUPPLY-SECHOLDER-001

The registry `latest` dist-tag for a locked package is npm's removed-for-security placeholder `0.0.1-security`, and the locked version is not that placeholder. Missing registry data produces no finding. `--offline` reads the cache only. Critical. Not downgraded by reachability. Remove the package, delete `node_modules`, reinstall from a clean lockfile, and rotate credentials the machine could read.
