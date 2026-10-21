# DEPS-SCRIPT-NODEGYP-001

**binding.gyp fetches a non-registry URL.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_NODEGYP=1`). CWE-829. Severity medium.

`binding.gyp` from the cached tarball descriptor, or from `node_modules/<name>/binding.gyp` when that file is present, contains an `http` or `https` URL whose host is not `registry.npmjs.org`. No URL, or only that host, means no finding. The file is not compiled.

## Remediation

Do not run node-gyp. Review the URL before any native build.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 195.
