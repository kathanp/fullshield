# SAST-XXE-001

**XML parsers with external entities enabled (`libxmljs` `noent: true`, `xml2js` custom entities) on tainted input.** CWE-611.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Disable external entity expansion (`noent: false`). Do not register custom SAX entities. Prefer a parser that rejects DTDs.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
