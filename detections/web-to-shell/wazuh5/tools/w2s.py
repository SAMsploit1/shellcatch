#!/usr/bin/env python3
"""Deploy and test the web-to-shell pack on Wazuh 5.0 (Content Manager API).

Run on a host that reaches the Wazuh indexer (the all-in-one node in the lab):

  sudo python3 w2s.py deploy  ../rules          # create/update rules in draft, promote to test
  sudo python3 w2s.py test    ../tests/cases.json  # replay fixtures through logtest
  sudo python3 w2s.py promote test              # test -> custom (production)
  sudo python3 w2s.py detector                  # detector for the custom-space rules
  sudo python3 w2s.py monitors ../monitors      # correlation monitors (Alerting)
  sudo python3 w2s.py alerts                    # correlation alerts raised so far
  sudo python3 w2s.py capture ../tests/cases.json  # refresh fixtures from live events
  sudo python3 w2s.py status

Credentials: WAZUH_INDEXER_ADMIN_PASSWORD, or read as root from
/etc/wazuh-indexer/export/credentials.env (the 5.0 installer writes it there).
Needs PyYAML (python3-yaml, present on Ubuntu/Debian by default).
"""
import base64
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request

import yaml

INTEGRATION = {
    "metadata": {
        "title": "web-to-shell",
        "author": "SAMspl0it",
        "description": (
            "Detects web runtimes (PHP-FPM, mod_php, Node.js) spawning processes: "
            "webshells, OS command injection and RCE post-exploitation. Rules only: "
            "it evaluates events normalized by the standard auditd, wazuh-fim and "
            "apache-http integrations."
        ),
        "references": ["https://github.com/SAMsploit1/shellcatch"],
    },
    "category": "system-activity",
    "enabled": True,
}
TITLE = INTEGRATION["metadata"]["title"]
BASE = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
CM = "/_plugins/_content_manager"


def password():
    pw = os.environ.get("WAZUH_INDEXER_ADMIN_PASSWORD")
    if pw:
        return pw
    env = pathlib.Path("/etc/wazuh-indexer/export/credentials.env")
    for line in env.read_text().splitlines():
        if line.startswith("WAZUH_INDEXER_ADMIN_PASSWORD="):
            return line.split("=", 1)[1].strip().strip("'\"")
    sys.exit("no indexer admin password found")


CTX = ssl.create_default_context(cafile=os.environ.get("WAZUH_INDEXER_CA"))
if not os.environ.get("WAZUH_INDEXER_CA"):  # lab default: self-signed install certs
    CTX.check_hostname = False
    CTX.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"admin:{password()}".encode()).decode()


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", AUTH)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": e.read().decode(errors="replace")}


def search(index, query, size=100):
    r = api("POST", f"/{index}/_search", {"size": size, "query": query})
    return [h["_source"] for h in r.get("hits", {}).get("hits", [])]


def find_integration(space):
    hits = search("wazuh-threatintel-integrations*", {"bool": {"filter": [
        {"term": {"document.metadata.title": TITLE}}, {"term": {"space.name": space}}]}})
    return hits[0]["document"] if hits else None


def draft_rules():
    hits = search("wazuh-threatintel-rules*", {"term": {"space.name": "draft"}}, size=500)
    return {h["document"]["metadata"]["title"]: h["document"]["id"] for h in hits}


def promote(space):
    preview = api("GET", f"{CM}/promote?space={space}")
    changes = preview.get("changes")
    if changes is None:
        sys.exit(f"promote preview failed: {preview}")
    n = sum(len(v) for k, v in changes.items() if k != "policy")
    r = api("POST", f"{CM}/promote", {"space": space, "changes": changes})
    print(f"promote {space}: {n} change(s) -> {r}")
    return r


def cmd_deploy(rules_dir):
    integ = find_integration("draft")
    if not integ:
        r = api("POST", f"{CM}/integrations", {"resource": INTEGRATION})
        if r.get("status") != 201:
            sys.exit(f"create integration failed: {r}")
        integ_id = r["message"]
        print(f"created integration {TITLE} {integ_id}")
    else:
        integ_id = integ["id"]
    existing = draft_rules()
    failed = 0
    for path in sorted(pathlib.Path(rules_dir).glob("*.yml")):
        rule = yaml.safe_load(path.read_text())
        rule.setdefault("logsource", {})["product"] = TITLE
        title = rule["metadata"]["title"]
        if title in existing:
            r = api("PUT", f"{CM}/rules/{existing[title]}", {"resource": rule})
            verb = "updated"
        else:
            r = api("POST", f"{CM}/rules", {"integration": integ_id, "resource": rule})
            verb = "created"
        ok = r.get("status") in (200, 201)
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {verb:7} {path.name}" + ("" if ok else f"\n     {r}"))
    if failed:
        sys.exit(f"{failed} rule(s) rejected; not promoting")
    promote("draft")


def cmd_test(cases_file, space="test"):
    cases_path = pathlib.Path(cases_file)
    cases = json.loads(cases_path.read_text())
    integ = find_integration(space)
    if not integ:
        sys.exit(f"integration {TITLE} not found in the {space} space")
    passed = 0
    for c in cases:
        fixture = cases_path.parent / "fixtures" / f"{c['name']}.json"
        if not fixture.exists():
            print(f"SKIP {c['name']}: no fixture (run capture)")
            continue
        event = json.loads(fixture.read_text())
        r = api("POST", f"{CM}/logtest/detection",
                {"space": space, "integration": integ["id"], "input": event})
        got = sorted(m["rule"]["title"] for m in r.get("message", {}).get("matches", []))
        want = sorted(c["expect"])
        # Expected entries are title prefixes, so templated titles stay readable.
        ok = len(got) == len(want) and all(g.startswith(w) for g, w in zip(got, want))
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'} {c['name']}")
        if not ok:
            print(f"     want {want}\n     got  {got}")
    total = len(cases)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


def cmd_capture(cases_file):
    """Save the newest live event matching each case's query as its fixture."""
    cases_path = pathlib.Path(cases_file)
    out = cases_path.parent / "fixtures"
    out.mkdir(exist_ok=True)
    for c in json.loads(cases_path.read_text()):
        r = api("POST", "/wazuh-events-v5-*/_search", {
            "size": 1, "sort": [{"@timestamp": "desc"}], "query": c["capture"]})
        hits = r.get("hits", {}).get("hits", [])
        if not hits:
            print(f"MISS {c['name']}")
            continue
        ev = hits[0]["_source"]
        # Fixtures are shared publicly: drop the raw log and host identity.
        ev.get("event", {}).pop("original", None)
        ev.get("wazuh", {}).pop("agent", None)
        ev.get("wazuh", {}).pop("cluster", None)
        (out / f"{c['name']}.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
        print(f"saved {c['name']}")


def cmd_detector():
    """Create (or refresh) the detector that runs the custom-space rules.

    A custom integration gets no detector of its own on promotion. One detector
    covers both event indices the pack reads: auditd and FIM events are in
    system-activity, web access logs in applications.
    """
    hits = search(".opensearch-sap-custom-rules-config", {"bool": {"filter": [
        {"term": {"rule.space": "custom"}}, {"term": {"rule.category": TITLE}}]}}, size=200)
    rule_ids = [{"id": h["rule"]["document"]["id"]} for h in hits]
    if not rule_ids:
        sys.exit("no custom-space rules found: run `promote test` first")
    body = {
        "type": "detector", "name": TITLE, "detector_type": TITLE, "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"detector_input": {
            "description": "web-to-shell custom rules over system-activity and applications events",
            "indices": ["wazuh-events-v5-system-activity", "wazuh-events-v5-applications"],
            "custom_rules": rule_ids, "pre_packaged_rules": []}}],
        "triggers": [],
    }
    r = api("POST", "/_plugins/_security_analytics/detectors/_search",
            {"size": 50, "query": {"match_all": {}}})
    existing = [h["_id"] for h in r.get("hits", {}).get("hits", [])
                if h["_source"].get("name") == TITLE]
    if existing:
        r = api("PUT", f"/_plugins/_security_analytics/detectors/{existing[0]}", body)
    else:
        r = api("POST", "/_plugins/_security_analytics/detectors", body)
    print(f"detector {'updated' if existing else 'created'}: "
          f"{r.get('_id', r)} with {len(rule_ids)} rule(s)")


def cmd_monitors(monitors_dir):
    """Create or update the correlation monitors (Alerting plugin) by name."""
    r = api("POST", "/_plugins/_alerting/monitors/_search",
            {"size": 200, "query": {"match_all": {}}})
    by_name = {h["_source"]["name"]: h["_id"] for h in r.get("hits", {}).get("hits", [])
               if "name" in h.get("_source", {})}
    for path in sorted(pathlib.Path(monitors_dir).glob("*.json")):
        m = json.loads(path.read_text())
        m.pop("_comment", None)
        if m["name"] in by_name:
            r = api("PUT", f"/_plugins/_alerting/monitors/{by_name[m['name']]}", m)
            verb = "updated"
        else:
            r = api("POST", "/_plugins/_alerting/monitors", m)
            verb = "created"
        ok = "_id" in r
        print(f"{'ok  ' if ok else 'FAIL'} {verb:7} {path.name}" + ("" if ok else f"\n     {r}"))


def cmd_alerts():
    r = api("GET", "/_plugins/_alerting/monitors/alerts?size=100&sortString=start_time&sortOrder=desc")
    for a in r.get("alerts", []):
        if not a.get("monitor_name", "").startswith(TITLE):
            continue
        keys = [b.get("bucket_keys") for b in [a.get("agg_alert_content") or {}]]
        print(f"{a['state']:9} {a['monitor_name']}  keys={keys}  start={a.get('start_time')}")


def cmd_status():
    for space in ("draft", "test", "custom"):
        i = find_integration(space)
        info = "-" if not i else f"{i['id']}  rules={len(i.get('rules', []))}"
        print(f"{space:7} {info}")
    r = api("POST", "/_plugins/_security_analytics/detectors/_search",
            {"size": 50, "query": {"match_all": {}}})
    for h in r.get("hits", {}).get("hits", []):
        s = h["_source"]
        if s.get("detector_type") == TITLE or s.get("name") == TITLE:
            di = s["inputs"][0]["detector_input"]
            print(f"detector {h['_id']} enabled={s['enabled']} source={s.get('source')} "
                  f"rules={len(di.get('custom_rules', []))} indices={di['indices']}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    {"deploy": cmd_deploy, "test": cmd_test, "promote": lambda s: promote(s),
     "capture": cmd_capture, "status": cmd_status, "detector": cmd_detector,
     "monitors": cmd_monitors, "alerts": cmd_alerts}[cmd](*args)


if __name__ == "__main__":
    main()
