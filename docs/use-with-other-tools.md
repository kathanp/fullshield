# Use FullShield next to other tools

FullShield does not run Semgrep, OSV-Scanner, npm audit, or Gitleaks. Run each tool yourself and keep the report file. Then pass those files to `fullshield ingest`.

`fullshield ingest <file...>` is the Phase 83 command. It stays off unless `FULLSHIELD_EXPERIMENTAL_INGEST=1` is set. It reads local files only: SARIF 2.1.0, OSV-Scanner `--format json`, `npm audit --json`, and Semgrep `--json`. It does not fetch those reports and it does not start the other tools.

## FullShield

```bash
npx fullshield scan --sarif fullshield.sarif
npx fullshield scan --json > fullshield.json
```

## Semgrep

```bash
semgrep scan --json --output semgrep.json .
```

## OSV-Scanner

```bash
osv-scanner scan -L package-lock.json --format json --output-file osv.json
```

## npm audit

```bash
npm audit --json > npm-audit.json
```

## Gitleaks

`gitleaks git` writes a SARIF file, which ingest accepts as SARIF 2.1.0.

```bash
gitleaks git --report-format sarif --report-path gitleaks.sarif
```

## Ingest

```bash
FULLSHIELD_EXPERIMENTAL_INGEST=1 npx fullshield ingest semgrep.json osv.json npm-audit.json gitleaks.sarif
```

Vulnerability reports for this repository follow [SECURITY.md](../SECURITY.md). Issue forms live in [config.yml](../.github/ISSUE_TEMPLATE/config.yml). The six required check names are in [branch-protection.md](branch-protection.md).
