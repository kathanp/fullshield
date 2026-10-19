# Use FullShield beside other tools

FullShield does not replace Semgrep, npm audit, OSV-Scanner, or a secrets scanner. Run them, then read their reports with `fullshield ingest` when `FULLSHIELD_EXPERIMENTAL_INGEST=1`.

```bash
npx semgrep scan --config p/javascript --json -o semgrep.json
osv-scanner --lockfile package-lock.json --format json > osv.json
npm audit --json > audit.json
npx fullshield scan --json > fullshield.json
FULLSHIELD_EXPERIMENTAL_INGEST=1 npx fullshield ingest semgrep.json osv.json audit.json --json
```

`ingest` reads local files only. It does not run those tools and it does not claim their results are correct. Reachability fields are added only when FullShield already has that evidence for the same package.
