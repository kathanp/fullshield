# DEPS-SCRIPT-SHEBANG-001

**Install script shebang is not node or a shell.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_SHEBANG=1`). CWE-78. Severity medium.

The install script file's first line is a shebang whose interpreter is not `node`, `sh`, or `bash`. `#!/usr/bin/env node` is not this finding. No shebang means no finding. The file is read from the cached tarball descriptor or from `node_modules/<name>/`. It is not executed.

## Remediation

Do not run the install script.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 205.
