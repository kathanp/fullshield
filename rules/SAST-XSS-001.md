# SAST-XSS-001

**Tainted HTML res.send, or unescaped <%- / {{{ in templates.** CWE-79.

## Remediation

Escape output. Use <%= in EJS and {{ in Handlebars. skip include.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
