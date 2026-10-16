# HOST-SSH-002

**Vulnerable OpenSSH without the `LoginGraceTime 0` mitigation.** CWE-693.

Emitted only when HOST-SSH-001 applies and effective sshd config (`sshd -T`, or `/etc/ssh/sshd_config` plus `Include` files if `sshd -T` is not permitted) does not have `logingracetime 0`.

## Remediation

Set `LoginGraceTime 0` and reload sshd as a temporary mitigation. Note: this enables a connection-exhaustion DoS. Prefer upgrading `openssh-server`. FullShield does not change sshd configuration.

Experimental: `fullshield host --experimental-host`.
