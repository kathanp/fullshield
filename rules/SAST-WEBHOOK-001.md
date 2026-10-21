# SAST-WEBHOOK-001

**Webhook without a verifier.** Experimental (`FULLSHIELD_EXPERIMENTAL_WEBHOOK=1`). CWE-345. Severity high.

A handler reads a provider listed in `models/webhooks.json` (Stripe, GitHub, Slack, Shopify, Twilio) and the file never calls that provider's verifier. An unknown provider is not a finding. A signature compared with `===` stays `SAST-TIMING-001`.

## Remediation

Verify the provider signature before using the event.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 99.
