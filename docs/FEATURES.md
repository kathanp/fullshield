# FullShield features (3.2.2)

Inventory of what **3.2.2** adds. Planning source: features2.md section C advanced extras C21–C24. This is a patch on 3.2.1. It adds no command, no CLI option, no rule id file, no package export, and no new `FULLSHIELD_EXPERIMENTAL_*` flag.

Default `scan --json` findings stay byte-identical to 3.2.1 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. `clean-app` stays at 0 findings on the default scan. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_SAST_PARITY`)

Same flag as 3.2.1.

- A same-file binding `name = req.body.<field>` that is later passed to `res.send(name)` or `res.end(name)` becomes one medium, low-confidence finding. `encodeURIComponent(name)` on that call is not a finding. The flag off does not add it.
- `prisma.$queryRaw` tagged templates, `publicProcedure.input(...)`, and `@Body() dto` do not become findings from this check.
- A route that reads `req.params.id` does not become an IDOR finding and cannot fail the default high CI gate.
- No cross-file cache is added. Default scan bytes stay the same as 3.2.1.
