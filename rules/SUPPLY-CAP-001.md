# SUPPLY-CAP-001

**Dependency capability denied by policy.** CWE-829. Experimental (`FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1`).

A direct dependency's static profile includes a capability listed under `deps.capabilityPolicy` as `deny`. This is not a statement that the package is malicious.

## Remediation

Remove the package or change the policy. FullShield does not install or execute the package.
