#!/usr/bin/env python3
"""Run wazuh-selfmon rule cases through the manager's logtest socket.

Usage (on the manager, as root):  python3 -I run_tests.py [cases.json]
Exit code 0 only if every case matches the expected rule id and level.
"""
import json, os, socket, struct, sys

SOCK = "/var/ossec/queue/sockets/logtest"
LOC = "/var/log/wazuh-selfmon/selfmon.json"


def logtest(event, token=None):
    req = {"version": 1, "command": "log_processing", "origin": {"name": "selfmon-tests", "module": "tests"},
           "parameters": {"event": event, "log_format": "json", "location": LOC}}
    if token:
        req["parameters"]["token"] = token
    data = json.dumps(req).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(struct.pack("<I", len(data)) + data)
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise SystemExit("logtest socket closed the connection: is wazuh-analysisd running?")
        hdr += chunk
    size = struct.unpack("<I", hdr)[0]
    buf = b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    return json.loads(buf)["data"]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases.json")
    cases = json.load(open(path))
    token, fails = None, 0
    for c in cases:
        # Cases in one "session" share a token so frequency rules see history.
        out = logtest(json.dumps({"selfmon": c["selfmon"]}), token if c.get("session") else None)
        if c.get("session"):
            token = out.get("token", token)
        rule = out.get("output", {}).get("rule", {})
        got = (rule.get("id"), rule.get("level"))
        want = (c["expect_id"], c["expect_level"])
        ok = got == want
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {c['name']:<44} expected {want[0]}/L{want[1]}  got {got[0]}/L{got[1]}"
              + ("" if ok else f"  desc={rule.get('description')!r}"))
    print(f"\n{len(cases) - fails}/{len(cases)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
