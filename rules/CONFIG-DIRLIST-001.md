# CONFIG-DIRLIST-001

**`serveIndex()` enables HTTP directory listing.** CWE-548.

## Remediation

Remove `serve-index`, or put the route behind authentication. Do not list ftp, logs, or key directories.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
