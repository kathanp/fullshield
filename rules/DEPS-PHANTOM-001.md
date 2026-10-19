# DEPS-PHANTOM-001

An import names a package that is not in `dependencies`, `devDependencies`, `optionalDependencies`, or `peerDependencies`. Node built-ins and relative imports are not packages. An import under `test/`, `tests/`, `__tests__/`, `scripts/`, `seeds/`, or a `*.test.*` / `*.spec.*` file is severity low. Other paths stay medium. A package declared in `devDependencies` is not reported on those paths.

## Remediation

Add the package to `package.json`, or remove the import.
