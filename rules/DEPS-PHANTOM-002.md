# DEPS-PHANTOM-002

**Undeclared dynamic import.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_PHANTOM_DEEP=1`). CWE-829. Severity medium.

A literal `import()`, `require.resolve`, or `createRequire(...)()` names a package that is not in `dependencies`, `devDependencies`, `optionalDependencies`, or `peerDependencies`. A declared name is not a finding. A non-literal argument is not a finding. Node built-ins and relative specifiers are not packages. This does not change `DEPS-PHANTOM-001`.

## Remediation

Add the package to `package.json`, or remove the dynamic import.

See `SECURITY_SCANNER_SPEC.md` Phase 242.
