# SUPPLY-PROV-001

Experimental (`FULLSHIELD_EXPERIMENTAL_PROVENANCE=1`). Informational registry signal for an installed package version. Severity is medium. The finding does not say the package is malicious. `DEPS-MALICIOUS-001` still comes only from an OSV `MAL-` advisory.

The registry host is `registry.npmjs.org` only. One packument request per package, at most 8 at a time, and `Retry-After` is honored. Results are stored in the Phase 62 registry cache (`<cache>/registry/<name>.json`). `--offline` reads that cache only.

Signals, when the packument lists the installed version:

- **provenance-regression** — an earlier version has `dist.attestations` and the installed version does not.
- **publisher-change** — the publishing user (`_npmUser` or `npmUser`) published none of the previous 10 versions.
- **new-release** — the same age check as Phase 62 (`releaseAgeLabel`, default 72 hours).

Missing cache data, a missing version, or an offline miss stays `unknown` and produces no finding.

False-positive risk: a maintainer can publish a young release, rotate the npm user, or drop attestations without anything being wrong. The negative fixture is an aged version that still has attestations and the same publisher as the previous versions; it produces no finding.
