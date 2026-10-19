# Priority score

`FULLSHIELD_EXPERIMENTAL_PRIORITY=1` adds `priority` (0–100) and `priorityFactors` to JSON. Severity is not changed. The function is deterministic: the same input returns the same score. There is no model and no network call.

`DEPS-MALICIOUS-001`, `SUPPLY-SECHOLDER-001`, and `SUPPLY-STEALER-001` are always 100.

| Factor | Points |
|---|---|
| severity critical | +80 |
| severity high | +60 |
| severity medium | +40 |
| severity low | +20 |
| severity info | +0 |
| confidence high | +10 |
| confidence medium | +0 |
| confidence low | −10 |
| reachability `reachable` or `symbol-reachable` | +10 |
| reachability `reachable-via-dependency` | +5 |
| reachability `reachability-unknown` | +0 |
| reachability `imported-not-called` or `symbol-not-called` | −5 |
| reachability `not-imported` | −15 |
| dev-only dependency | −15 |
| unauthenticated route reaches the sink | +10 |
| sink class sqli, cmdi, or ssrf | +5 |
| sink class xss, path, or nosqli | +3 |
| each extra agreeing source after the first | +5 |
| KEV flag, only when Phase 56 cache data is present | +10 |

The total is clamped to 0–100. Console order with the flag on is priority, then severity, then file. JSON keeps the existing finding order and adds the two fields.
