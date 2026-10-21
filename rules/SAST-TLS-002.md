# SAST-TLS-002

**NODE_TLS_REJECT_UNAUTHORIZED disabled.** Experimental (`FULLSHIELD_EXPERIMENTAL_TLS=1`). CWE-295. Severity high.

`process.env.NODE_TLS_REJECT_UNAUTHORIZED` set to `0` in source, or the same variable set to 0 in a `Dockerfile` `ENV`, `package.json` scripts, a compose `environment` entry, or a committed `.env*` file.

Test paths are severity low. A `NODE_ENV !== 'production'` guard in source is severity medium.

## Remediation

Turn TLS verification back on. Do not set `NODE_TLS_REJECT_UNAUTHORIZED=0`.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 95.
