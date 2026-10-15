# SAST-MASSASSIGN-001

**`Model.create(req.body)` / `update(req.body)` / `Object.assign(user, req.body)` without an allowlist or schema.** CWE-915.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Pick allowed fields, or parse with zod/joi/yup before create/update. Never pass `req.body` straight into an ORM or `Object.assign`.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
