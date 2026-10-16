# SAST-UPLOAD-001

**`multer` / `busboy` / `formidable` without a file size limit or type filter; uploaded `originalname` used in a filesystem path.** CWE-434.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Set `limits.fileSize` (or `maxFileSize`) and a MIME/extension allow-list. Store files under a generated name, never `originalname`.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
