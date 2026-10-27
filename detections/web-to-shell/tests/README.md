# Tests

Validates the ruleset against a live Wazuh `logtest` engine — not a mock, so a
PASS means the real analysis pipeline (decoders, `if_sid` chains, rule order,
frequency state) produces that rule ID.

## Run

```bash
./run.sh                         # default: wazuh/wazuh-manager:4.14.8
./run.sh wazuh/wazuh-manager:4.9.0
```

Needs Docker. Spins up a throwaway manager with the ruleset mounted, waits for
`analysisd`, runs every case, and tears it down.

## Files

- **build_cases.py** — generates `cases.json`. Encodes auditd arguments exactly
  as the daemon does: a printable, space-free, quote-free argument is written
  quoted, everything else as uppercase hex. That is why the reverse-shell cases
  carry hex `a2=` fields — it matches what a real agent ships, and it is why the
  rules match both the plain and hex forms.
- **logtest.py** — talks to `/var/ossec/queue/sockets/logtest` over its
  length-prefixed JSON protocol. Each single-event case runs in a fresh session;
  the correlation checks replay multiple events in one session to drive rule
  `100550`. Run with the manager's framework Python.
- **cases.json** — generated; the current fixtures.

## What's covered (42 cases)

- Every rule tier: shell spawn, discovery, transfer tools, interpreters
  (script file vs inline `-c`/`-e`/`-r`), base64, reverse shells (`/dev/tcp`,
  `mkfifo`, `nc -e`, `socat exec`), web payloads, upload-dir hits, `cmd=`
  params.
- **Syscall coverage**: the same command via `execveat` and via the 32-bit
  `execve` table must hit the same rule.
- **Known-good**: PHP `mail()` → `sh -c "/usr/sbin/sendmail -t -i"` (with and
  without `-f`) lands on 100511 at level 3, but `sendmail -t -i;id` must not.
- **False-positive guards**: `rsync -e ssh` and `GIT_SSH_COMMAND='ssh -i ...'`
  must classify as a plain shell spawn (100510), not a reverse shell.
- **Stock-rule overlap**: python/scp/`ps aux`/lscpu events, which stock ruleset
  `0850-audit_rules.xml` also claims, must still reach our rules via the shared
  `if_sid`. Likewise web payloads that stock `31104`/`31106` claim
  (`wget%`, `cd%20`) must still reach 100560/100562.
- **Isolation**: a non-web user's python stays on the stock rule (92600); PHP
  and Node activity do not cross-correlate into 100550.

FIM (layer 3) can't be exercised through logtest. It was validated separately
by running syscheck on a live manager and dropping files into the monitored
paths; all of `100570`/`100571`/`100572` fired, and `.jpg` plus `node_modules/`
were correctly ignored. A separate 4.14.8 check confirmed `restrict` is sregex:
`.php$` alerts on `shell.php` but not `shellXphp`, and `\.php$` alerts only on
a file literally named `x\.php`.
