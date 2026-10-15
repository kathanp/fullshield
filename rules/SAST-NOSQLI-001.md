# SAST-NOSQLI-001

**req.body/req.query passed as a Mongo filter, a tainted `$where` string, or request input used as a Mongo filter value without coercion, schema validation, or mongo-sanitize.** CWE-943.

Constructed filters such as `{ password: req.body.password }` are medium confidence. They are not flagged when the value is `String()` / `Number()` / `Boolean()`, a zod/joi/yup `.parse`, `mongo-sanitize`, or `express-mongo-sanitize` middleware. SQL ORM `{ where }` is not a Mongo filter.

## Remediation

Coerce or schema-validate each filter field; never pass the request object through. Prefer `mongo-sanitize` or an allow-listed filter object.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
