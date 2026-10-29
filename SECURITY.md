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
| 3.2.2 | This tree. |
| 3.2.1 | Previous. |
| 3.1.2 | Previous. |
| 3.1.1 | Previous. |
| 3.0.0 | Previous. |
| 2.4.0 | Previous. |
| 2.3.0 | Previous. |
| 2.2.0 | Previous. |
| 2.1.0 | Tagged `v2.1.0`. |
| 2.0.2 | Tagged `v2.0.2`. |
| 2.0.1 | Tagged `v2.0.1`. |
| 1.8.0 | Tagged `v1.8.0`. |
| 1.7.0 | Tagged `v1.7.0`. |
| 1.6.0 | Tagged `v1.6.0`. |
| 1.5.0 | Tagged `v1.5.0`. |
| 1.4.0 | Tagged `v1.4.0`. |
| 1.3.1 | Tagged `v1.3.1`. |
| 1.3.0 | Tagged `v1.3.0`. |
| 1.2.0 | Tagged `v1.2.0`. |
| 1.0.x | Supported. 1.0.1 was published 2026-10-21, with provenance. |
| < 1.0.0 | Not the current release. Use 1.0.1. |

The package enforces Node >= 22.13 (`package.json` `engines` and `doctor`). A minor release is required for a new rule, command, flag, export, or stable-output change.

## Please do not

- Open a public issue with a working exploit
- Demand a bounty (there is none at this time)
