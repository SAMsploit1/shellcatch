# shellcatch

Validated Wazuh detections for the Wazuh Ambassador program.

**📖 Read the write-up:** https://samsploit1.github.io/shellcatch/

---

## Detections

### [web-to-shell (PHP & Node.js)](detections/web-to-shell)
Detects web runtimes spawning processes — webshells, command injection, and RCE
(the React2Shell class). Three layers (auditd process execution, web-request
payloads, FIM webshell drops), all MITRE-mapped, validated 30/30 against a live
`wazuh-manager` logtest engine. Includes a Docker lab and step-by-step
[install guide](detections/web-to-shell/INSTALL.md).

![Threat Hunting dashboard](detections/web-to-shell/screenshots/1-threat-hunting-dashboard.png)

---

See [SUBMISSIONS.md](SUBMISSIONS.md) for the full contribution log.
