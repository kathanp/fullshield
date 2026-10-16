# Security policy

## Reporting a vulnerability

Please report vulnerabilities through **GitHub private vulnerability advisories** on this repository (Security → Advisories → New draft security advisory). Do not open a public issue for a suspected vulnerability.

We aim to respond within **7 days**.

If you cannot use private advisories, email the maintainer listed on the npm package page and say that you have a security report (do not include exploit details in the first message).

## Scope

In-scope: the `fullshield` CLI, library, and `fullshield/runtime` middleware as published on npm.

Out of scope: findings in `test/fixtures/**` (intentionally vulnerable), third-party apps used only as benchmarks (`NodeGoat`, DVNA), and issues that require you to scan a host you do not own.

## Supported versions

| Version | Status |
|---|---|
| 0.1.x | Supported. 0.1.3 is the current npm release. |
| 0.0.x | Deprecated placeholders. Use >= 0.1.0. |

Security fixes ship as patch releases on 0.1.x until the next minor. A minor release is required for a new rule, command, flag, export, or stable-output change.

## Please do not

- Open a public issue with a working exploit
- Demand a bounty (there is none at this time)
