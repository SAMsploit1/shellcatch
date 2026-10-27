# Deploying the web-to-shell detection

Step-by-step install for a production Wazuh deployment. For a disposable test
environment, use [the lab](lab/) instead (isolated network only, never on a
manager that serves production agents); to validate the rules without any
agent, use [the test suite](tests/).

The detection has two sides: **agent** (collects the data) and **manager**
(runs the rules). Do both.

---

## 1. On each web server (Wazuh agent)

### 1a. auditd rules — process execution

Edit the service-account names in
[auditd/60-web-to-shell.rules](auditd/60-web-to-shell.rules) to match your
hosts first. The key requirement: **PHP runs as `www-data`/`apache`/`nginx`,
and Node.js runs under its own dedicated service account** (the rules key on
that account to mean "spawned by the web app").

```bash
sudo cp auditd/60-web-to-shell.rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | grep web_exec        # should list the loaded rules
```

### 1b. Agent config — audit log, access log, FIM

Append the collection + FIM block to the agent's config:

```bash
sudo tee -a /var/ossec/etc/ossec.conf < wazuh/agent_ossec.conf
sudo systemctl restart wazuh-agent
```

Check the paths in [wazuh/agent_ossec.conf](wazuh/agent_ossec.conf) match your
webroots (`/var/www`) and Node app directory (`/opt/nodeapp`).

> Managing many agents? Put the same block in a shared agent group instead
> (`/var/ossec/etc/shared/<group>/agent.conf` on the manager) so it pushes to
> every agent in the group.

---

## 2. On the Wazuh manager

### 2a. Install the rules

```bash
sudo cp wazuh/web_to_shell_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/web_to_shell_rules.xml
```

Rule IDs `100500`–`100599` must be free in your custom ruleset. If you already
use that range, renumber the `id=` and `if_sid=` references consistently.

### 2b. Validate before restarting

```bash
sudo /var/ossec/bin/wazuh-logtest -v
# paste a sample audit line; confirm it hits a 1005xx rule with no XML errors
```

### 2c. Apply

```bash
sudo systemctl restart wazuh-manager
# confirm the rules loaded cleanly:
sudo grep -iE "ERROR|CRITICAL" /var/ossec/logs/ossec.log | tail
```

---

## 3. Verify in the dashboard

Dashboard → **Threat Hunting**, add a filter `rule.groups: web_to_shell`.
Trigger a test from a web server:

```bash
# on an agent, as the web user — benign discovery command
sudo -u www-data id
```

You should see rule `100520` within a few seconds. See the
[screenshots](screenshots/) for what a populated view looks like.

---

## 4. Tune (expected, not optional)

The one rule that needs attention first is **`100510`** (shell spawned,
level 8), because some apps legitimately shell out: ImageMagick, wkhtmltopdf,
git deploy hooks, Composer. PHP `mail()` → sendmail is already handled by rule
`100511` (level 3). See the README's Tuning section for the full list.
Silence a known-good command with a level-0 child rule in your local rules:

```xml
<rule id="100590" level="0">
  <if_sid>100510</if_sid>
  <field name="audit.exe" type="pcre2">/usr/bin/convert$</field>
  <description>Web-to-shell: known-good ImageMagick call (ignored)</description>
</rule>
```

Also: rule `100522` treats the PHP CLI as a web-spawned interpreter — drop
`php` from its regex if your app calls `php` as a subprocess on purpose.

---

## Uninstall

```bash
# manager
sudo rm /var/ossec/etc/rules/web_to_shell_rules.xml
sudo systemctl restart wazuh-manager
# agent
sudo rm /etc/audit/rules.d/60-web-to-shell.rules && sudo augenrules --load
# then remove the appended block from /var/ossec/etc/ossec.conf and restart the agent
```
