# URL audit

Draft from `src/net/hosts.ts`. The decision column is blank.

| host | when it is contacted | allowed or NEEDS-HUMAN |
|---|---|---|
| api.osv.dev | default allowlist | |
| registry.npmjs.org | default allowlist | |
| localhost | default allowlist | |
| 127.0.0.1 | default allowlist | |
| ::1 | default allowlist | |
| api.anthropic.com | only when FULLSHIELD_AI_LIVE=1 | |
| api.openai.com | only when FULLSHIELD_AI_LIVE=1 | |
| sts.amazonaws.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | |
| api.github.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | |
| api.stripe.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | |
| slack.com | only when FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1 | |
