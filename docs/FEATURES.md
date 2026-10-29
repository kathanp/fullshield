# FullShield features (3.3.1)

Inventory of what **3.3.1** adds. Planning source: features2.md section D, items 21–23. This is a minor on 3.2.2. It adds no command and no CLI option. It adds one experimental flag.

Default `scan --json` findings stay byte-identical to 3.2.2 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. `clean-app` stays at 0 findings on the default scan. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD`)

Off unless the flag is `1`.

- Default runtime mode stays monitor. With the flag off, an existing block mode is unchanged.
- With the flag on, a requested block mode blocks only the `sql` and `shell` sinks. `path`, `nosql`, `ssrf`, `proto`, and `ssti` stay monitor.
- A runtime event may carry `webhookJson`: one JSON object with `schema` 1, `kind`, `action`, and `ruleId`. At most 5 of those bodies are produced per 60 seconds. The body is not posted and contains no request sample. The flag off adds no `webhookJson`.
- This does not claim to prevent attacks. eBPF and network-layer detection are not implemented. External alerts stay on `ingest` of a file you already have.

No new host. No new rule file.
