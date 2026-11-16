#!/usr/bin/env bash
# Wazuh lab helper for Codespaces (also works on any machine with Docker).
#
#   lab.sh test [image]      web-to-shell logtest suite (throwaway manager)
#   lab.sh selfmon [image]   wazuh-selfmon logtest suite (throwaway manager)
#   lab.sh all [image]       both suites
#   lab.sh manager [image]   long-running manager for manual wazuh-logtest
#   lab.sh shell             open wazuh-logtest in the running manager
#   lab.sh stop              remove the long-running manager
#   lab.sh pull [image]      pre-pull the manager image
#
# Default image: $WAZUH_IMAGE or wazuh/wazuh-manager:4.14.8.
#
# Not possible here: auditd (no kernel audit access inside Codespaces) and the
# Wazuh 5.0 Content Manager / indexer tests. Use the Azure lab for those.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.8}"
MANAGER="shellcatch-manager"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

need_docker() {
  command -v docker >/dev/null || { echo "[!] docker not found" >&2; exit 1; }
  docker info >/dev/null 2>&1 || { echo "[!] docker daemon not running" >&2; exit 1; }
}

wait_logtest() { # $1 = container
  echo -n "[+] Waiting for analysisd"
  for _ in $(seq 1 90); do
    if docker exec "$1" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; then echo " ready"; return 0; fi
    echo -n "."; sleep 2
  done
  echo; echo "[!] logtest socket never appeared; recent errors:" >&2
  docker exec "$1" grep -E "ERROR|CRITICAL" /var/ossec/logs/ossec.log 2>/dev/null | tail -20 >&2 || true
  return 1
}

run_selfmon() {
  local image="$1" name="selfmon-test-$$" d="$ROOT/detections/wazuh-selfmon"
  trap 'docker rm -f "'"$name"'" >/dev/null 2>&1 || true' RETURN
  echo "[+] Starting $image for wazuh-selfmon"
  docker run -d --name "$name" \
    -v "$d/rules/wazuh_selfmon_rules.xml:/var/ossec/etc/rules/wazuh_selfmon_rules.xml:ro" \
    -v "$d/tests:/tests:ro" "$image" >/dev/null
  wait_logtest "$name"
  docker exec "$name" /var/ossec/framework/python/bin/python3 -I /tests/run_tests.py /tests/cases.json
}

cmd="${1:-help}"; image="${2:-$DEFAULT_IMAGE}"
case "$cmd" in
  test)    need_docker; bash "$ROOT/detections/web-to-shell/tests/run.sh" "$image" ;;
  selfmon) need_docker; run_selfmon "$image" ;;
  all)     need_docker; rc=0
           bash "$ROOT/detections/web-to-shell/tests/run.sh" "$image" || rc=1
           run_selfmon "$image" || rc=1
           [[ $rc -eq 0 ]] && echo "[+] ALL SUITES PASSED" || echo "[!] SOME SUITES FAILED"
           exit $rc ;;
  manager) need_docker
           docker rm -f "$MANAGER" >/dev/null 2>&1 || true
           docker run -d --name "$MANAGER" \
             -v "$ROOT/detections/web-to-shell/wazuh/web_to_shell_rules.xml:/var/ossec/etc/rules/web_to_shell_rules.xml:ro" \
             -v "$ROOT/detections/wazuh-selfmon/rules/wazuh_selfmon_rules.xml:/var/ossec/etc/rules/wazuh_selfmon_rules.xml:ro" \
             "$image" >/dev/null
           wait_logtest "$MANAGER"
           echo "[+] Manager '$MANAGER' running. Next: lab.sh shell   (stop with: lab.sh stop)" ;;
  shell)   need_docker; docker exec -it "$MANAGER" /var/ossec/bin/wazuh-logtest ;;
  stop)    need_docker; docker rm -f "$MANAGER" >/dev/null 2>&1 && echo "[+] Removed $MANAGER" || echo "[=] Not running" ;;
  pull)    need_docker; docker pull -q "$image" ;;
  help|-h|--help) usage ;;
  *)       usage; exit 1 ;;
esac
