# HOST-SSH-003

**Possible SSH authentication-timeout exploitation attempts.** CWE-307.

Counts `Timeout before authentication` lines per source IP in the last 24h from `journalctl -u ssh*` or `/var/log/auth.log` when those files are readable **without sudo**. Never a confirmed attack.

## Remediation

Use fail2ban or CrowdSec to block abusive sources. FullShield does not install firewall rules or block IPs.

Experimental: `fullshield host --experimental-host`.
