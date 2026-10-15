# SAST-DESER-001

**Tainted input into `node-serialize.unserialize`, unsafe `js-yaml` schemas, `funcster`, or `serialize-javascript` eval paths.** CWE-502.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Do not deserialize untrusted data into objects or code. Use JSON with a schema, or `js-yaml` `JSON_SCHEMA` / `safeLoad`. Never `eval` serialized JavaScript.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
