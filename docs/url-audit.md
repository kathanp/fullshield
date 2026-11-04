# URL audit

Draft from `src/net/hosts.ts`. The decision column is blank. `suggested` is not a decision.

| host | when it is contacted | allowed or NEEDS-HUMAN | suggested | reason |
|---|---|---|---|---|
| api.osv.dev | default allowlist | | allowed | Default advisory lookup. It sends package names and versions, not source code. |
| registry.npmjs.org | default allowlist | | allowed | Default package metadata lookup. It does not send source code. |
| localhost | default allowlist | | allowed | Loopback only. |
| 127.0.0.1 | default allowlist | | allowed | Loopback only. |
| ::1 | default allowlist | | allowed | Loopback only. |
| api.anthropic.com | only when FULLSHIELD_AI_LIVE=1 | | NEEDS-HUMAN | The live AI flag can send code or prompts off the machine. |
| api.openai.com | only when FULLSHIELD_AI_LIVE=1 | | NEEDS-HUMAN | The live AI flag can send code or prompts off the machine. |
| sts.amazonaws.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | | NEEDS-HUMAN | Secret verification can send credential material to AWS. |
| api.github.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | | NEEDS-HUMAN | Secret verification can send a token to GitHub. |
| api.stripe.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | | NEEDS-HUMAN | Secret verification can send a key to Stripe. |
| slack.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | | NEEDS-HUMAN | Secret verification can send a webhook or token to Slack. |
