# DEPS-TARBALL-HASH-001

**Tarball bytes do not match dist.integrity.** Critical. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HASH=1`). CWE-353.

Direct production dependency only. The sha512 of cached tarball bytes is compared with the lock integrity, or with packument `dist.integrity` when the lock has none. A mismatch stops extraction for that package. No network fetch.

## Remediation

Replace the cached tarball with the registry.npmjs.org artifact that matches the lock integrity.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 168.
