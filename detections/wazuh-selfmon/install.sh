#!/bin/sh
# Install wazuh-selfmon on a Wazuh 4.x manager (all-in-one or manager node).
# Run as root from the wazuh-selfmon directory. Re-running is safe.
set -eu
cd "$(dirname "$0")"
OSSEC=/var/ossec

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$OSSEC/bin/wazuh-control" ] || { echo "no Wazuh manager in $OSSEC" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

install -m 750 probe/wazuh-selfmon /usr/local/sbin/wazuh-selfmon
[ -f /etc/wazuh-selfmon.conf ] || install -m 640 config/wazuh-selfmon.conf /etc/wazuh-selfmon.conf
install -d -m 750 /var/log/wazuh-selfmon /var/lib/wazuh-selfmon
touch /var/log/wazuh-selfmon/selfmon.json

clash=$(grep -l 'rule id="1008[01][0-9]"' "$OSSEC"/etc/rules/*.xml 2>/dev/null | grep -v wazuh_selfmon_rules.xml || true)
[ -z "$clash" ] || { echo "rule IDs 100800-100819 already used in: $clash" >&2; exit 1; }
install -o wazuh -g wazuh -m 660 rules/wazuh_selfmon_rules.xml "$OSSEC/etc/rules/"

if ! grep -q '/var/log/wazuh-selfmon/selfmon.json' "$OSSEC/etc/ossec.conf"; then
  cp -p "$OSSEC/etc/ossec.conf" "$OSSEC/etc/ossec.conf.bak-selfmon"
  { echo; echo "<ossec_config>"; grep -v '^<!--' config/ossec.conf.snippet; echo "</ossec_config>"; } \
    >> "$OSSEC/etc/ossec.conf"
fi

install -m 644 systemd/wazuh-selfmon.service systemd/wazuh-selfmon.timer /etc/systemd/system/
systemctl daemon-reload

echo "Checking the rules load..."
"$OSSEC/bin/wazuh-analysisd" -t >/dev/null 2>&1 || { echo "wazuh-analysisd -t failed: check ossec.log" >&2; exit 1; }
systemctl restart wazuh-manager
systemctl enable --now wazuh-selfmon.timer

echo "Done. Dry run:"
/usr/local/sbin/wazuh-selfmon --dry-run --all | python3 -c '
import sys, json
for l in sys.stdin:
    s = json.loads(l)["selfmon"]
    print(s["status"].ljust(9), s["check"].ljust(20), s["message"])'
echo
echo "Next: set NOTIFY_URL in /etc/wazuh-selfmon.conf. Without it, a dead manager can't tell you it is dead."
