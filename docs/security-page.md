# Security page

This page is about the `fullshield` package. It is not a SOC2 report and it is not a company audit.

A cloud-free scan stays on the machine that runs the CLI. FullShield does not upload findings, source, or lockfiles to a FullShield service. This package does not run a hosted scanner.

A default scan contacts `api.osv.dev` when it is not offline. `registry.npmjs.org` is contacted only when an experimental npm, provenance, or supply flag turns that fetch on. Both hosts are in `src/net/hosts.ts`. These hosts are fetched and are not in that list; they are under review: `api.anthropic.com`, `api.openai.com`, `sts.amazonaws.com`, `api.github.com`, `api.stripe.com`, and `slack.com`. `digest --file` reads a local JSON file and does not fetch.

Report a vulnerability through the process in [SECURITY.md](../SECURITY.md).
