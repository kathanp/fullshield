# FullShield features (3.4.1)

Inventory of what **3.4.1** adds. Planning source: features2.md section E, items 24–28. This is a minor on 3.3.2. It adds `init --tour`, `init --stack <name>`, and `digest --file <path>`.

Default `scan --json` findings stay byte-identical to 3.3.2 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. `clean-app` stays at 0 findings on the default scan. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_ADOPT`)

Off unless the flag is `1`. With the flag off, `--tour`, `--stack`, and `digest` throw `FS-E025` before they read or write a file.

- `init --tour` prints five steps: scan, fix dry-run, init CI, no project tests, and no scan of the home directory. It writes no file.
- `init --stack <name>` writes `fullshield.stack.md` for `express`, `nest`, `next`, `fastify`, or `hono`. The file names monitor mode and does not suppress a finding. An unknown name throws `FS-E025` and writes nothing.
- `digest --file <path>` reads a local JSON array and prints the sorted npm `id` values. It does not fetch. Other ecosystems are omitted. This is not a published CVE count.
- No letter grade, no recall number, and no benchmark number is added. The security page says a cloud-free scan sends no customer scan data. It does not claim SOC2.

No new host. No new rule file. No eBPF.
