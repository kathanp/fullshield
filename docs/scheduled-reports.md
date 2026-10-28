# Scheduled scans → Markdown reports

FullShield is a **CLI**. It does not stay running inside your app server. You have two ways to scan:

1. **When you want.** `npx fullshield scan` prints a report in the terminal and exits.
2. **Every 2 hours.** `npx fullshield schedule install` registers an OS timer. Each run starts, scans, writes one Markdown file, deletes reports past the newest 60, and exits.

Twelve runs a day for five days is 60 files. The folder is `fullShieldReport/` at the repo root. The file name includes the date and the time so those 12 runs do not overwrite each other:

`fullShieldReport/fullShieldReport_20261028_1400.md`

The stamp is the machine's local time: `YYYYMMDD_HHMM`.

## Mental model

| Approach | Use? | Notes |
|---|---|---|
| Manual `npx fullshield scan` | Yes | On-demand terminal report. Does not create `fullShieldReport/` or edit `.gitignore` |
| `npx fullshield schedule install` | Yes | Every 2 hours. Writes the dated file above and keeps 60 |
| Pre-commit / CI on PR | Yes | Gate merges; `init` can scaffold this |
| `watch` on a schedule | Yes | Deps-only; alerts on **new** OSV hits |
| Daemon inside the Node app that keeps rescanning the repo | No | The timer is outside the process. Each `schedule run` exits |

Optional **runtime** middleware (`shieldGuard` / experimental RASP) watches **requests**, not the codebase. That is separate from scheduled code scans.

## On demand

```bash
npx fullshield scan
npx fullshield scan --markdown report.md
```

`scan` runs deps, secrets, sast, and config. `--markdown <file>` writes a Markdown report to the path you pass. That path is not the scheduled folder, and this command does not prune old files or edit `.gitignore`.

## Every 2 hours

```bash
npx fullshield schedule install
npx fullshield schedule status
npx fullshield schedule run
npx fullshield schedule uninstall
```

| Command | What it does |
|---|---|
| `schedule install` | Creates `fullShieldReport/`, adds `fullShieldReport/` to `.gitignore` once, and registers the timer |
| `schedule run` | One scan, one dated Markdown file, then prune. This is what the timer calls |
| `schedule status` | Whether the timer is installed, and how many dated reports are on disk |
| `schedule uninstall` | Removes the timer. Leaves the folder, the reports, and the `.gitignore` line |

`install` registers a user timer. It does not use sudo.

| System | Timer |
|---|---|
| macOS | LaunchAgent, on the hour at 00:00, 02:00, …, 22:00 local time |
| Linux | User crontab: `0 */2 * * *` |
| Windows | Task Scheduler, every 2 hours |

The timer runs `schedule run` for that project with the Node binary recorded at install time, then exits. A second `install` in the same project replaces FullShield's timer entry and leaves the rest of your crontab alone.

`run` writes the Markdown file even when findings are still open. It does not exit 1 for a standing high finding, and it does not send Slack or email. Use `notify` when you want that. After `run`, `.fullshield/last-scan.json` is the same summary `notify` already reads.

Retention counts files named `fullShieldReport_YYYYMMDD_HHMM.md`. The newest 60 stay. Older matches are deleted. Other files in the folder stay. The file just written is kept even if the clock moves backward.

`install` appends `fullShieldReport/` to `.gitignore` when that line is missing, and creates `.gitignore` when the project does not have one. If the line is already there, the file is left as it is. `scan` and `schedule run` do not edit `.gitignore`.

Reports can include file paths and secret **locations**. The gitignore line is there so a later commit does not pick the folder up by accident.

## One-shot Markdown from `scan`

```bash
npx fullshield scan --markdown fullShieldReport.md
```

### Useful `scan` options for reports

| Option | Purpose |
|---|---|
| `--markdown <file>` | Write a Markdown report to this path (e.g. `report.md`) |
| `--html <file>` | Write an HTML report |
| `--sarif <file>` | Write SARIF 2.1.0 (IDEs / GitHub code scanning) |
| `--json` | Machine-readable JSON on stdout |
| `--all` | Print every finding in the console (no 20-row cap). JSON / Markdown / HTML / SARIF / baseline / `--fail-on` already use the full list |
| `--fail-on <severity>` | Exit 1 if any finding is at or above this severity (`info` / `low` / `medium` / `high` / `critical`) |
| `--modules <list>` | Comma-separated subset: e.g. `deps`, `secrets`, `sast`, `config` |
| `--offline` | Use the OSV cache only (no network) |
| `--staged` | Scan only git-staged files (pre-commit style; usually not for a full-day schedule) |
| `--config <path>` | Path to `fullshield.config.json` |
| `--update-baseline` | Record current findings as accepted; later CI fails only on **new** ones |

Experimental report-related flags (off unless enabled):

| Option / flag | Purpose |
|---|---|
| `FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1` or `--experimental-ci-reports` | Enable CI report writers |
| `--github-annotations <file>` | GitHub Actions workflow commands |
| `--junit <file>` | JUnit XML |
| `--gitlab <file>` | GitLab Code Quality JSON |
| `FULLSHIELD_EXPERIMENTAL_POLICY=1` + `--pr-summary` | Deterministic Markdown of **new** findings vs baseline for PR comments (no AI) |
| `FULLSHIELD_EXPERIMENTAL_DIFF=1` + `fullshield diff before.json after.json` | Compare two `scan --json` files; does not scan |

Save JSON from an on-demand scan if you want diffs or tooling later:

```bash
npx fullshield scan --json --markdown report.md > .fullshield/last-scheduled.json
```

(`.fullshield/last-scan.json` is also written by `scan` and by `schedule run`. `notify` / `watch` read that file depending on the command.)

## CI

`schedule install` is for a machine that keeps its disk (a laptop or a build host). A GitHub Actions runner does not. Prefer uploading one report as an artifact over committing `fullShieldReport/`.

`init` installs a **daily** deps `watch` workflow (`templates/github-watch.yml`: `0 6 * * *`). A workflow can still call one shot:

```yaml
name: FullShield scheduled report
on:
  workflow_dispatch:
jobs:
  report:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: '22'
      - run: npm ci
      - run: npx fullshield schedule run
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: fullshield-report
          path: fullShieldReport/
```

That job writes one dated file for the run. It does not install a timer on the runner.

## `watch` (deps only, new CVEs)

For dependency CVE churn, use `watch` instead of (or in addition to) a full `scan`:

```bash
npx fullshield watch --fail-on high
npx fullshield watch --webhook https://example.com/hooks/fullshield
npx fullshield watch --offline
```

| Option | Purpose |
|---|---|
| `--fail-on <severity>` | Exit 1 if a **new** finding is at or above this severity |
| `--webhook <url>` | POST only when there are new findings |
| `--offline` | OSV cache only |

`watch` rescans **deps**, compares to the last scan, and alerts only on **new** OSV-style hits. It does not write `fullShieldReport/`. Pair `schedule install` when you want the Markdown history.

`npx fullshield init` can add `.github/workflows/fullshield-watch.yml` (daily schedule + `workflow_dispatch`).

## `notify` (push the last scan summary)

After a scan or a `schedule run` has written the last-scan summary:

```bash
npx fullshield notify --slack
npx fullshield notify --slack https://hooks.slack.com/services/...
npx fullshield notify --webhook https://example.com/hooks/fullshield
npx fullshield notify --email
```

| Option / env | Purpose |
|---|---|
| `--slack [url]` | Slack incoming webhook, or `$FULLSHIELD_SLACK_WEBHOOK` if URL omitted |
| `--webhook <url>` | Generic JSON webhook |
| `--email` | SMTP via `FULLSHIELD_SMTP_HOST`, `FULLSHIELD_SMTP_PORT` (default 25), `FULLSHIELD_SMTP_FROM`, `FULLSHIELD_NOTIFY_EMAIL` |

`schedule run` does not call `notify`. Identical findings every 2 hours are noisy. Call `notify` from your own wrapper when you want an alert, or use `watch` for new dependency hits.

## Recommended product choices

1. **On-demand scan stays `npx fullshield scan`.** It does not touch the report folder or `.gitignore`.
2. **History lives in `fullShieldReport/`.** One file per run, local `YYYYMMDD_HHMM`, 60 files kept.
3. **The timer is installed once** with `schedule install`. It is not a process that sleeps inside the app.
4. **Gitignore the folder** at install time. Do not commit the reports. Paths and secret-adjacent context can leak via git history.
5. **Do not fail the 2-hour job on a standing finding.** `schedule run` writes the file either way. Use `watch`, a baseline, or `diff` when an alert should mean something new.
6. **Heavy repos.** A full SAST scan 12 times a day can be expensive. CI `--fail-on` still gates merges. `watch` stays the daily new-CVE check.

## What this is not

- Not continuous scanning inside the production server.
- Not a replacement for PR CI gates (`scan --fail-on`).
- Not automatic fix application (`fix --apply` is explicit and expects a clean git tree).
- Not a GitHub Actions cron that commits the report folder.

## Quick reference

```bash
# On demand (terminal)
npx fullshield scan

# On demand → one Markdown file you name
npx fullshield scan --markdown report.md

# Every 2 hours → fullShieldReport/fullShieldReport_YYYYMMDD_HHMM.md
npx fullshield schedule install
npx fullshield schedule status
npx fullshield schedule run
npx fullshield schedule uninstall

# Deps-only new CVE alert
npx fullshield watch --fail-on high --webhook "$WEBHOOK_URL"

# Push last scan summary
npx fullshield notify --slack
npx fullshield notify --webhook "$WEBHOOK_URL"
npx fullshield notify --email

# Scaffold CI + daily watch workflow
npx fullshield init
```

Public command overview: [README.md](../README.md). Frozen stable surface: [stability.md](stability.md).
