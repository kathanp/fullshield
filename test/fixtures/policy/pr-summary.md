# FullShield PR summary

2 new finding(s) versus baseline.

## high (1)

- [`SAST-SQLI-001`](https://github.com/kathanp/fullshield/blob/main/rules/SAST-SQLI-001.md) `src/db.js:12` — Tainted input concatenated into a SQL query.

## medium (1)

- [`CONFIG-HELMET-001`](https://github.com/kathanp/fullshield/blob/main/rules/CONFIG-HELMET-001.md) `src/app.js:4` — Express app is missing helmet().
