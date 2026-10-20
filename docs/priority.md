# Deterministic priority

`FULLSHIELD_EXPERIMENTAL_PRIORITY=1` (or `scan --experimental-priority`) adds `priority` (0–100) and `priorityFactors[]` to JSON. The flag is off by default. With the flag off, JSON is unchanged and severity is unchanged. Priority never changes severity.

The score is a pure function. Same input, same score. No machine learning. No network. Phase 56 is not implemented, so KEV and EPSS are omitted.

## Always 100

These rule IDs score 100. The only factor is `always`. Other factors are not applied.

| rule id | priority |
| --- | --- |
| DEPS-MALICIOUS-001 | 100 |
| SUPPLY-SECHOLDER-001 | 100 |
| SUPPLY-STEALER-001 | 100 |

## Points

Start at 0. Add every factor below. Clamp the total to 0–100. Factor rows keep their raw points when the total is clamped.

Factor order: severity, confidence, reachability, route, devOnly, sink, sources.

### severity

| severity | points |
| --- | --- |
| critical | 70 |
| high | 55 |
| medium | 40 |
| low | 20 |
| info | 5 |

### confidence

| confidence | points |
| --- | --- |
| high | 10 |
| medium | 0 |
| low | -10 |

### reachability

| class | points |
| --- | --- |
| reachable | 10 |
| symbol-reachable | 10 |
| reachable-via-dependency | 5 |
| reachability-unknown | 0 |
| absent | 0 |
| imported-not-called | -5 |
| symbol-not-called | -5 |
| not-imported | -15 |

### route exposure

An unauthenticated route that reaches the sink scores up. A dev-only dependency scores down. The two are separate factors.

| exposure | points |
| --- | --- |
| unauthenticated | 10 |
| authenticated | 0 |
| unknown | 0 |
| dev-only | -20 |

`SAST-AUTH-001`, and any finding whose message says `no auth middleware`, is `unauthenticated`. A message containing `(dev-only)` sets dev-only. Anything else is unknown and not dev-only.

### sink class

An explicit `sinkClass` wins. Otherwise the rule id is mapped. Secret findings with no mapped rule use `credential`. Every other rule uses `none` (0).

| class | points | rule ids |
| --- | --- | --- |
| rce | 10 | SAST-CMDI-001, SAST-EVAL-001 |
| injection | 8 | SAST-SQLI-001, SAST-NOSQLI-001 |
| exposure | 5 | SAST-SSRF-001, SAST-PATH-001, SAST-XSS-001, SAST-REDIRECT-001 |
| proto | 4 | SAST-PROTO-001 |
| credential | 2 | SAST-JWT-001, SAST-CRYPTO-001, SAST-AUTH-001, secret rules |
| none | 0 | everything else |

### agreeing sources

Phase 83. Until ingest attaches `sources[]`, a FullShield finding counts as one source.

| count | points |
| --- | --- |
| 0 or 1 | 0 |
| 2 | 5 |
| 3 | 10 |
| 4 or more | 15 |

## Console

With the flag on, the console sorts by priority (highest first), then severity, then file. With the flag off, the existing console order is kept.
