# DEPS-PHANTOM-001

An import names a package that is not in `dependencies`, `devDependencies`, `optionalDependencies`, or `peerDependencies`. Node built-ins and relative imports are not packages.

## Remediation

Add the package to `package.json`, or remove the import.
