# User-supplied Semgrep-style rules

FullShield can compile a small subset of rules you already wrote. It does not bundle, mirror, or download Semgrep registry rules or any other third-party rule pack.

Results may differ from Semgrep.

The rules file is read only when `FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES=1` or `--experimental-semgrep-rules` is set. With the flag off, the file is not parsed. Pass the path as `semgrepRules` in `fullshield.config.json` or as `--semgrep-rules`.

`yaml` is an optional peer. It is loaded with `import()` only after the flag is on. If it is missing, the command tells you to install yaml to use user-supplied semgrep rules.

## Supported

A file has one top-level key, `rules`. Each rule has:

- `id`
- `message`
- `severity`: `critical`, `high`, `medium`, `low`, `info`, or the Semgrep words `CRITICAL`, `ERROR` (high), `WARNING` (medium), `INFO` (low)
- `languages`: `javascript` and `typescript` only
- `pattern`
- `pattern-either`: a list of `{ pattern }`
- `pattern-not`: one pattern string
- `pattern-inside`: one pattern string
- metavariables written `$X` (the same name must be the same expression)
- `...` in the argument list of a call or `new` only
- `mode: taint` with `pattern-sources`, `pattern-sinks`, and optional `pattern-sanitizers`, each a list of `{ pattern }`

Search mode uses `pattern` and/or `pattern-either`, then drops matches of `pattern-not`, then keeps a match only when `pattern-inside` matches an ancestor.

Taint mode is mapped onto FullShield's existing taint engine. `req.body` and the other request sources that engine already tracks flow into the sink. A `pattern-sources` call such as `readTicket()` is tainted when it appears at the sink or was assigned in the same function. A `pattern-sanitizers` pattern suppresses the sink when the sink value matches it, or was assigned from a call that matches it. This is not Semgrep's taint solver.

Compiled taint rules keep the Phase 57 fields `id`, `severity`, `message`, `sources`, `sinks`, and sanitizers. Search rules keep `id`, `severity`, and `message` plus the pattern fields above.

Findings use `ruleId: CUSTOM-<id>` and `source: user-rule`.

## Rejected

Any other key, language, or pattern form fails the whole file with `FS-E012`. The message names the construct and the rule id. No rule from that file is applied.

Not supported, among other things: `pattern-regex`, `metavariable-regex`, `pattern-where`, `pattern-not-inside`, `focus-metavariable`, languages other than `javascript` and `typescript`, and `...` outside a call or `new` argument list.
