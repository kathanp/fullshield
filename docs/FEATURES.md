# FullShield features (3.2.1)

Inventory of what **3.2.1** adds. Planning source: features2.md section C, items 15–20, basic only. This is a minor on 3.1.2. It adds `scan --counts` and `fix --finding`. It adds no rule id, no package export, and one new `FULLSHIELD_EXPERIMENTAL_*` flag.

Default `scan --json` findings stay byte-identical to 3.1.2 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. No stable rule id is removed. No stable finding field is removed. This version does not scan Python or any language other than Node.js and TypeScript. It does not publish precision or recall. It does not download a rule registry. It does not assign a letter grade. `clean-app` stays at 0 findings on the default scan. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_SAST_PARITY`)

- `scan --counts` prints one JSON object of counts by severity and reachability. The object has no grade, no score, and no certification text. The flag off refuses the option before the scan. Default `scan --json` does not gain this object.
- A local YAML file named `fullshield.rules.yml` in the project directory is read only when the flag is on. Each rule has `schema` 1, a string `pattern`, a string `message`, and a severity of `low`, `medium`, or `high`. Matching lines become findings. The file is never fetched. A missing file adds nothing. Invalid YAML or a rule outside that shape throws before findings are emitted.
- `fix --finding <ruleId>:<file>:<line>` writes the one safe fix for that finding and leaves every other file untouched. It still requires a clean git tree unless `--force` is already set. It does not run the project test script. The flag off refuses the option before a scan.
- The HTML report, when the flag is on, lists `source` and `sink` file and line for a taint finding that already has both. It does not invent an edge. The flag off leaves the HTML report unchanged.
- README states that other languages are out of scope and that reviewed recall for untouched apps is not published.
