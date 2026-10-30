# FullShield and npm audit

`npm audit` reports advisories in the lockfile. FullShield's default scan classifies those lockfile CVEs by reachability: a package that is not imported is not the same result as a package that is called.

This page does not state a finding count. It does not say FullShield finds more issues than npm audit. A count that is not from a named fixture run is not a result.
