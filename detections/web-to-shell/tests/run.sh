#!/usr/bin/env bash
# Validate the web-to-shell ruleset against a throwaway Wazuh manager container.
# Requires Docker. Takes ~1 minute.
#
#   ./run.sh [image]
#
# Spins up the manager with the rules mounted, generates the test cases, runs
# them through the live logtest engine, and tears the container down.
set -euo pipefail

IMAGE="${1:-wazuh/wazuh-manager:4.14.8}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
NAME="w2s-runsh-$$"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[+] Generating test cases"
python3 "$HERE/build_cases.py" > "$HERE/cases.json"

echo "[+] Starting $IMAGE"
docker run -d --name "$NAME" \
  -v "$ROOT/wazuh/web_to_shell_rules.xml:/var/ossec/etc/rules/web_to_shell_rules.xml:ro" \
  -v "$HERE:/tests:ro" \
  "$IMAGE" >/dev/null

echo -n "[+] Waiting for analysisd"
for i in $(seq 1 60); do
  if docker exec "$NAME" grep -q "CRITICAL" /var/ossec/logs/ossec.log 2>/dev/null; then
    echo; echo "[!] Rules failed to load:"
    docker exec "$NAME" grep -E "ERROR|CRITICAL" /var/ossec/logs/ossec.log | grep -iv "cluster\|indexer\|connect"
    exit 1
  fi
  docker exec -w /tests "$NAME" /var/ossec/framework/python/bin/python3 \
    -c "import logtest; logtest.process('x')" >/dev/null 2>&1 && { echo " ready"; break; }
  echo -n "."; sleep 2
done

echo "[+] Running cases"
docker exec -w /tests "$NAME" /var/ossec/framework/python/bin/python3 logtest.py cases.json
