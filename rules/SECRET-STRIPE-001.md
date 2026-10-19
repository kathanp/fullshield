# SECRET-STRIPE-001

**Stripe secret key.** CWE-798.

## Remediation

Rotate the key and move it to a secret manager.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://docs.stripe.com/keys
