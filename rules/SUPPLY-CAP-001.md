# SUPPLY-CAP-001

**Dependency capability denied by policy (static).** CWE-829.

Experimental (`FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1`). A `deps.capabilityPolicy` `deny` rule matched a capability read from already-installed package files. High. Never executes package code and never runs install scripts. Absent from the default scan.

Capabilities: `child_process`, `net` (`net` / `http` / `https` / `dgram` / `fetch`), `fs_write`, `env` (`process.env`), `eval` (`eval`, `new Function`, `vm`), `native` (`.node`, `binding.gyp`), `dynamic_require`, `install_script` (`preinstall` / `install` / `postinstall`), `obfuscation` (Phase 70 `eval` of a decoded string, a 64+ hex run, an 80+ base64 run, or eight `\xNN` escapes).

`fullshield deps --capabilities` prints each direct dependency's own capabilities plus those of its transitive packages, with the package version that introduces each one. `deps-diff` adds `newCapabilities` only when this flag is also set. A bump is reported only when the previous integrity is already in the capability cache.

## False-positive risk

The check is textual. A comment, string, or example that mentions `process.env`, `writeFile`, or `require('net')` is counted. The negative fixture is a package that only calls `fs.readFileSync` and whose `scripts.test` is not an install script. `warn` policy does not emit this rule. A deny glob that names a capability the package does not have does not emit it.

## Remediation

Remove the package, or change `deps.capabilityPolicy` if the capability is expected. Do not run the package's install script to investigate it.
