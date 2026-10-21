# CONFIG-ELECTRON-003

**BrowserWindow loads a remote URL without navigation guards.** Experimental (`FULLSHIELD_EXPERIMENTAL_ELECTRON=1`). CWE-749. Severity medium.

`loadURL` of an `http:` or `https:` URL when the file has neither `setWindowOpenHandler` nor `will-navigate`. `loadFile` and `file:` are not remote.

## Remediation

Guard navigation with `setWindowOpenHandler` or `will-navigate`.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 102.
