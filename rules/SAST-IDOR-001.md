# SAST-IDOR-001

**Handler loads by id without an ownership check.** Experimental (`FULLSHIELD_EXPERIMENTAL_IDOR=1`). CWE-639. Severity low. Confidence low. `source` is `rule`, so `failsCi` is false at every fail-on threshold.

An authenticated-looking route with an `:id` param loads by `findById`, `findByPk`, `findUnique`, or `WHERE id =` and the file never references `req.user`, `req.session.user`, or `ctx.state.user`. A middleware name matching `admin`, `role`, `permission`, or `authorize` is not a finding. This is a hint and is not promoted.

## Remediation

Scope the query to the authenticated user.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 107.
