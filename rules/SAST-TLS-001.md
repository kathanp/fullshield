# SAST-TLS-001

**TLS certificate verification disabled.** Experimental (`FULLSHIELD_EXPERIMENTAL_TLS=1`). CWE-295. Severity high.

`rejectUnauthorized: false` or `checkServerIdentity` returning `undefined`, in options passed to `https.request` / `https.get`, `tls.connect`, `new https.Agent`, axios, undici `Agent({ connect })`, got, or `ssl` / `tls` options. A `ca` option on the same object is not a finding. An unresolved variable is not a finding.

Files under `test/`, `__tests__/`, `*.test.*`, `*.spec.*`, or `scripts/dev*` are severity low with `context: "test"`. The same option inside `process.env.NODE_ENV !== 'production'` is severity medium.

## Remediation

Turn TLS verification back on. Do not ship `rejectUnauthorized: false`.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 95.
