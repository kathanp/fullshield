# WORKERS-SQL-001

**BullMQ job payload reaches SQL.** CWE-89. Requires `FULLSHIELD_EXPERIMENTAL_WORKERS=1` and `--modules workers`.

A BullMQ `Worker` callback passes `job.data` to `query` or `execute`. A field passed through `Number`, `parseInt`, or `parseFloat` is not this finding. A constant query is not this finding.

## Remediation

Parse the payload and pass a checked field, or pass a constant. Do not pass the raw job payload into SQL.
