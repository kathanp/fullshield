# FullShield features (3.3.2)

Inventory of what **3.3.2** adds. Planning source: features2.md section D advanced extras D24–D27. This is a patch on 3.3.1. It adds no command, no CLI option, no rule id file, no package export, and no new `FULLSHIELD_EXPERIMENTAL_*` flag.

Default `scan --json` findings stay byte-identical to 3.3.1 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. `clean-app` stays at 0 findings on the default scan. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD`)

Same flag as 3.3.1.

- A SQL runtime event stores `fingerprint`, a short hash of the statement after quoted text and numbers are collapsed. The 3.3.1 `webhookJson` object stays the same keys. The flag off sets no fingerprint.
- Lines in the text you pass that contain `.query(` or `$queryRaw` are reported when that fingerprint is non-empty. This does not scan the project and does not change default scan findings.
- `confirm` prints `"ok": false` and exits 1 when any confirmation is `unconfirmed` and this flag is on. The flag off still prints `"ok": true`. An unconfirmed result is not a pass.
- A runtime sample larger than 4096 bytes sets `overCap`. This is not a DLP product. The flag off does not set `overCap`.
- While this flag is on, `FULLSHIELD_RASP_MODE=block-experimental` is the block mode and the value `block` stays monitor. The flag off still treats `block` as block.

No eBPF. No new host. No new rule file.
