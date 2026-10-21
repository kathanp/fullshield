# DEPS-TARBALL-ENV-001

**Package entry passes process.env to a request.** Critical. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_ENV=1`). CWE-200.

Direct production dependency only. A `main` or `exports` file passes the whole `process.env` object to `fetch`, `http.request`, or `https.request`. `process.env.NODE_ENV` is not this finding. Fixture hosts are `example.invalid`.

## Remediation

Do not pass the process.env object to those calls.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 185.
