#!/usr/bin/env python3
"""Run tests/cases.json through a live Wazuh manager's logtest engine.

Talks to the logtest socket directly, so it must run on the manager (or in the
manager container) with the framework Python:

  /var/ossec/framework/python/bin/python3 logtest.py cases.json

Each case runs in a fresh session so earlier events can't affect it, then
two multi-event sessions check the correlation rule 100550.

A case whose "expect" is null passes if none of the web-to-shell rules
(1005xx) fire.
"""
import json
import socket
import struct
import sys

SOCKET = "/var/ossec/queue/sockets/logtest"
LOCATION = "(victim) any->/var/log/audit/audit.log"


def call(payload):
    data = json.dumps(payload).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(struct.pack("<I", len(data)) + data)
        size = struct.unpack("<I", s.recv(4))[0]
        buf = b""
        while len(buf) < size:
            buf += s.recv(size - len(buf))
    return json.loads(buf)


def process(log, token=None):
    params = {"event": log, "log_format": "syslog", "location": LOCATION}
    if token:
        params["token"] = token
    resp = call({"version": 1, "command": "log_processing", "parameters": params})
    if resp.get("error"):
        raise RuntimeError(resp)
    data = resp["data"]
    return data["output"].get("rule", {}), data.get("token")


def close(token):
    call({"version": 1, "command": "remove_session", "parameters": {"token": token}})


def main(path):
    cases = json.load(open(path))
    failures = 0
    for case in cases:
        rule, token = process(case["log"])
        close(token)
        got = rule.get("id")
        expect = case["expect"]
        ok = got == expect or (expect is None and not (got or "").startswith("1005"))
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {case['name']:<45} expected={expect} got={got} "
              f"level={rule.get('level')}")

    # Correlation: two post-exploitation commands by the same account fire
    # 100550; commands by different accounts (PHP vs Node) must not.
    by_name = {c["name"]: c["log"] for c in cases}
    checks = [
        ("correlation: php id + php whoami -> 100550", ["php: id", "php: whoami"], "100550"),
        ("correlation: php id + node uname -> no 100550", ["php: id", "node: uname -a"], "100520"),
    ]
    for label, names, expect in checks:
        token = None
        for name in names:
            last, token = process(by_name[name], token)
        close(token)
        ok = last.get("id") == expect
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {label:<45} expected={expect} got={last.get('id')} "
              f"level={last.get('level')}")
    total = len(cases) + len(checks)

    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "cases.json"))
