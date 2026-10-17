# SAST-SKIP-001

**A source file was not parsed.** Severity info.

The file is larger than `sast.maxFileBytes` (default 1 MB) or it contains NUL bytes. This is a skip notice, not a vulnerability.

## Remediation

Raise `sast.maxFileBytes` in `fullshield.config.json` when the file should be parsed. Generated and vendored trees are excluded before this check.
