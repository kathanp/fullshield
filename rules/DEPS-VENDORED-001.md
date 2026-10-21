# DEPS-VENDORED-001

**Vendored library with an OSV advisory.** Experimental (`FULLSHIELD_EXPERIMENTAL_VENDORED=1`). CWE-1104. Severity comes from OSV.

A JavaScript file under `public/`, `static/`, `assets/`, `vendor/`, `lib/`, or any `*.min.js`, whose banner or exported `VERSION` matches `models/vendored.json`. No match means no finding. The version is never guessed from size or a hash. `--offline` uses the OSV cache; a cache miss is no finding. Reachability is `vendored`.

## Remediation

Replace the file. Do not edit the vendored copy in place.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 104.
