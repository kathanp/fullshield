# HOST-SSH-001

**OpenSSH package version is in the CVE-2024-6387 (regreSSHion) range.** CWE-364.

Uses the distro package version (`dpkg-query` / `rpm` / `apk`), not `ssh -V`. Distro OSV advisories win so backported fixes are not flagged. Upstream fallback: 8.5p1 ≤ v < 9.8p1, or v < 4.4p1.

Severity is **critical** only when the version is vulnerable, `LoginGraceTime` is not 0, and sshd is listening on a non-loopback address.

## Remediation

Upgrade `openssh-server` via the distro package manager. Temporary mitigation: `LoginGraceTime 0` (enables a connection-exhaustion DoS). FullShield does not auto-patch or stop OS/SSH exploits.

Experimental: `fullshield host --experimental-host`.
