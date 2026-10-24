#!/usr/bin/env bash
# Build the web-to-shell lab victim on a throwaway Ubuntu 22.04/24.04 VM.
#
# Installs nginx + PHP-FPM + Node.js with two deliberately vulnerable apps,
# loads the auditd rules, and (when WAZUH_MANAGER is set) installs and
# configures the Wazuh agent.
#
#   sudo WAZUH_MANAGER=192.168.56.10 ./setup-victim.sh
#
# Never run this on a machine reachable from an untrusted network.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"

echo "[+] Packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  nginx php-fpm nodejs auditd curl iputils-ping python3 >/dev/null

echo "[+] Node.js service account"
id nodeapp >/dev/null 2>&1 || useradd --system --home /opt/nodeapp --shell /usr/sbin/nologin nodeapp

echo "[+] Vulnerable PHP app -> /var/www/html"
install -m 0644 "$HERE/apps/php/ping.php" "$HERE/apps/php/upload.php" /var/www/html/
install -d -o www-data -g www-data /var/www/html/uploads

echo "[+] Vulnerable Node app -> /opt/nodeapp"
install -d -o nodeapp -g nodeapp /opt/nodeapp
install -m 0644 -o nodeapp -g nodeapp "$HERE/apps/node/server.js" /opt/nodeapp/
cat > /etc/systemd/system/nodeapp.service <<'EOF'
[Unit]
Description=Web-to-shell lab Node.js app
After=network.target

[Service]
User=nodeapp
WorkingDirectory=/opt/nodeapp
ExecStart=/usr/bin/node /opt/nodeapp/server.js
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now nodeapp >/dev/null

echo "[+] nginx site (PHP everywhere, including uploads/: vulnerable by design)"
FPM_SOCK="$(ls /run/php/php*-fpm.sock | head -1)"
cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    root /var/www/html;
    index index.html;

    location ~ \.(php|phtml)\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$FPM_SOCK;
    }

    location /node/ {
        proxy_pass http://127.0.0.1:3000/;
    }
}
EOF
systemctl restart nginx "$(basename "$FPM_SOCK" .sock)"

echo "[+] auditd rules"
install -m 0640 "$ROOT/auditd/60-web-to-shell.rules" /etc/audit/rules.d/
augenrules --load >/dev/null
auditctl -l | grep -c web_exec | xargs echo "    loaded rules:"

if [[ -n "${WAZUH_MANAGER:-}" ]]; then
  echo "[+] Wazuh agent -> $WAZUH_MANAGER"
  if [[ ! -x /var/ossec/bin/wazuh-control ]]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER="$WAZUH_MANAGER" DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wazuh-agent >/dev/null
  fi
  # ossec.conf accepts multiple <ossec_config> blocks; append ours once.
  grep -q "Web-to-shell: agent-side" /var/ossec/etc/ossec.conf \
    || cat "$ROOT/wazuh/agent_ossec.conf" >> /var/ossec/etc/ossec.conf
  systemctl enable --now wazuh-agent >/dev/null
  systemctl restart wazuh-agent
else
  echo "[!] WAZUH_MANAGER not set: skipped agent install. Merge wazuh/agent_ossec.conf by hand."
fi

echo "[+] Done. Smoke test:"
curl -s "http://127.0.0.1/ping.php?host=127.0.0.1" | head -1
curl -s "http://127.0.0.1/node/ping?host=127.0.0.1" | head -1
