# SAST-CIPHER-001

**Weak cipher mode or IV.** Experimental (`FULLSHIELD_EXPERIMENTAL_CRYPTO2=1`). CWE-327. Severity high.

`createCipheriv` with an `*-ecb` algorithm, deprecated `createCipher` / `createDecipher`, or an IV that is a string literal, `Buffer.from` of a literal, or `Buffer.alloc`. `randomBytes` is not a finding.

Test paths use the phase 95 test-context rule (severity low, `context: "test"`).

## Remediation

Use an authenticated mode such as `aes-256-gcm` and a random IV from `randomBytes`.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 96.
