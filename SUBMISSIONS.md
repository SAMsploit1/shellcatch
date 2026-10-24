# Wazuh community submissions log

Running record of contributions for the Wazuh Ambassador program.

Repo: https://github.com/SAMsploit1/shellcatch
Site: https://samsploit1.github.io/shellcatch/

| Date | Type | Title | Link / location | Status |
|------|------|-------|-----------------|--------|
| 2026-10-24 | Detection content | Web-to-shell detection (PHP & Node.js) | [detections/web-to-shell](detections/web-to-shell) | Published — rules, lab, tests, INSTALL, live dashboard screenshots |
| 2026-10-24 | Write-up / site | Catching the moment a web app becomes a shell | [site](https://samsploit1.github.io/shellcatch/) · [source](content/blog-web-to-shell.md) | Published on GitHub Pages — republish on dev.to/Medium optional |

---

## Contribution 1 — Web-to-shell detection

**Type:** Detection content / ruleset + technical write-up
**Platform:** Wazuh 4.14 (stock decoders; should hold across 4.x)
**Repo:** https://github.com/SAMsploit1/shellcatch
**Article:** https://samsploit1.github.io/shellcatch/
**MITRE ATT&CK:** T1505.003, T1059.004, T1190, T1105, T1140, T1546

**Description (short):**
Open-source Wazuh ruleset that detects web runtimes (PHP-FPM, mod_php, Node.js)
spawning processes — the common endpoint of webshells, OS command injection, and
RCE such as the React2Shell class. It combines three detection layers (auditd
process execution, web-access-log payloads, and real-time FIM for webshell
drops), all mapped to MITRE ATT&CK. Ships with a self-contained vulnerable lab, a
30-case test suite validated against a live `wazuh-manager` logtest engine, a
step-by-step install guide, and a Medium-style write-up.

**Description (one-liner):**
A validated three-layer Wazuh detection for web-to-shell attacks (PHP & Node.js)
— webshells, command injection, and RCE — with a Docker lab, a 30-case test
suite, and a published write-up.

**What's included:** `web_to_shell_rules.xml` (IDs 100500–100599), auditd rules,
agent `ossec.conf` snippet, Docker lab (vulnerable PHP + Node apps), 30-case
logtest suite + Docker runner, INSTALL.md, live dashboard screenshots, blog post,
GitHub Pages site.

**Evidence:** 30/30 logtest cases pass on a clean container; FIM verified live;
17 real alerts across all three layers shown in the Threat Hunting dashboard.

## Pipeline / ideas

- Upstream the ruleset as a PR to `wazuh/wazuh-ruleset`
- Alert integration (Discord / Telegram / ntfy)
- SCA policy for an app with no stock CIS coverage
