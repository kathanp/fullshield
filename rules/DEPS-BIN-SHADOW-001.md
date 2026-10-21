# DEPS-BIN-SHADOW-001

**Dependency bin shadows a Node builtin or the root package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_BINSHADOW=1`). CWE-427. Severity medium.

A direct dependency's bin name is `fs`, `path`, `child_process`, `http`, `https`, `net`, `tls`, `crypto`, `os`, or `dns`, or it equals a bin name of the root package. The bin is read from `node_modules/<name>/package.json` when that file exists. Otherwise it is read from the lock entry `bin`, then from the packument cache at `{cache}/registry/<name>.json` for the locked version. No local file and no cache entry for that version is not a finding. A bin named `my-cli` is not this finding unless the root package uses the same name.

## Remediation

Rename the bin so it is not a Node builtin and not a root package bin.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 146.
