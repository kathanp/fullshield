# CONFIG-ELECTRON-001

**Unsafe Electron webPreferences.** Experimental (`FULLSHIELD_EXPERIMENTAL_ELECTRON=1`). CWE-749. Severity high.

One finding for each of `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, and `allowRunningInsecureContent: true` inside `webPreferences`. The project must depend on `electron`.

## Remediation

Harden the Electron window. Do not enable Node integration for remote content.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 102.
