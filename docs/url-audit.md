# URL audit

> Decisions drafted by AI from the source code. Not human-reviewed.

Draft from `src/net/hosts.ts`. The decision column is copied from `suggested`. A human has not accepted it.

| host | when it is contacted | allowed or NEEDS-HUMAN | suggested | reason |
|---|---|---|---|---|
| api.osv.dev | default allowlist | allowed | allowed | Default advisory lookup. It sends package names and versions, not source code. |
| registry.npmjs.org | default allowlist | allowed | allowed | Default package metadata lookup. It does not send source code. |
| localhost | default allowlist | allowed | allowed | Loopback only. |
| 127.0.0.1 | default allowlist | allowed | allowed | Loopback only. |
| ::1 | default allowlist | allowed | allowed | Loopback only. |
| api.anthropic.com | only when FULLSHIELD_AI_LIVE=1 | NEEDS-HUMAN | NEEDS-HUMAN | The live AI flag can send code or prompts off the machine. |
| api.openai.com | only when FULLSHIELD_AI_LIVE=1 | NEEDS-HUMAN | NEEDS-HUMAN | The live AI flag can send code or prompts off the machine. |
| sts.amazonaws.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | NEEDS-HUMAN | NEEDS-HUMAN | Secret verification can send credential material to AWS. |
| api.github.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | NEEDS-HUMAN | NEEDS-HUMAN | Secret verification can send a token to GitHub. |
| api.stripe.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | NEEDS-HUMAN | NEEDS-HUMAN | Secret verification can send a key to Stripe. |
| slack.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | NEEDS-HUMAN | NEEDS-HUMAN | Secret verification can send a webhook or token to Slack. |
