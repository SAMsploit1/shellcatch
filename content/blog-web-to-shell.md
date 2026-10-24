# Catching the moment a web app becomes a shell: web-to-shell detection in Wazuh

*By Vigan Bytyqi — Wazuh Ambassador*

Most web compromises, whatever the entry point, converge on one move: the web
application starts running operating-system commands. A classic PHP webshell
does it. An OS command injection in a Node.js app does it. So does the latest
deserialization or server-side RCE — including the React/Next.js "React2Shell"
class of bugs that made the rounds recently. The vulnerability of the week
changes; the thing it does next rarely does.

That gives defenders a durable chokepoint. A PHP-FPM worker or a Node.js server
almost never has a legitimate reason to run `id`, `curl`, or `/bin/sh`. When it
does, something is wrong. Wazuh is well placed to see it — but ships no rule for
it out of the box. This post walks through a three-layer detection that fills
the gap, and, just as importantly, how I validated it against a real Wazuh
manager so you can trust it before it ever sees production traffic.

The full ruleset, lab, and test suite are on GitHub: [link].

## The core idea: the service account is the signal

The cleanest signal is process lineage — "php-fpm spawned bash." The catch is
that Linux's audit subsystem (`auditd`), which is where this event is richest,
records the *user* that called `execve()`, not the parent process name. So
rather than fight for parent-child data, the detection keys on the **account**
the runtime runs as, and treats it as a proxy for "this came from the web app."

That works cleanly as long as each runtime has its own identity:

- PHP-FPM and Apache already run as `www-data` (or `apache`/`nginx`). Good.
- Node.js, by convention, often runs as root or a developer's login user. That
  ruins the signal. **Run your Node app under a dedicated service account.**
  It is good hygiene regardless, and it is what makes this detection precise.

With that in place, the audit rule is tiny — log every `execve` by the web
accounts:

```
-a always,exit -F arch=b64 -S execve -F euid=www-data -k web_exec_php
-a always,exit -F arch=b64 -S execve -F euid=nodeapp  -k web_exec_node
```

## Three layers

Process execution is the heart of it, but two more layers add context and catch
the attack earlier or later in its lifecycle.

**Layer 1 — process execution (auditd).** The tiered rules escalate with
intent:

| Behaviour | Example | Level |
|-----------|---------|-------|
| Shell spawned | `sh -c '…'` | 8 |
| Discovery | `id`, `whoami`, `uname` | 12 |
| Download / transfer | `curl`, `wget`, `scp` | 12 |
| Interpreter | `python -c`, `perl -e` | 10 |
| Reverse shell | `/dev/tcp`, `mkfifo`, `nc -e`, `socat exec` | 15 |

And a correlation rule: three post-exploitation commands from the *same* web
account within two minutes is almost certainly someone typing into a webshell —
that escalates to level 14 on its own.

**Layer 2 — web access logs.** Before the shell ever spawns, the request often
carries the payload: `?page=system('id')`, `/bin/sh` in a parameter,
`require('child_process')` in a query string, or a hit on a freshly uploaded
`.php` in an `uploads/` directory. These fire off the stock web-accesslog
decoder.

**Layer 3 — file integrity monitoring.** The webshell has to land somewhere.
Real-time FIM on the webroot flags new `.php`/`.phtml`/`.phar` files, new `.js`
in the Node app directory, and tampering with `.htaccess` or `.user.ini` (a
common trick to make PHP execute innocuous-looking file types).

Everything is mapped to MITRE ATT&CK — T1505.003 (Web Shell), T1059.004 (Unix
Shell), T1190 (Exploit Public-Facing Application), and friends.

## The part most rule packs skip: proving it works

It is easy to write XML that *looks* like a detection. It is harder to know it
fires on what you intend and stays quiet on what you don't. I built the ruleset
against a throwaway `wazuh/wazuh-manager` container and drove 30 cases through
the live `logtest` engine — the real analysis pipeline, not a mock.

Two things only surfaced because of that.

**auditd hex-encoding.** auditd writes a command argument as a quoted string
only when it is printable with no spaces or quotes; otherwise it writes it as
uppercase hex. So a reverse shell like `sh -c "bash -i >& /dev/tcp/…"` arrives
on the wire as `a2=62617368202D69…`. A rule matching the plaintext `/dev/tcp`
would miss the real event entirely. The generator in the test suite encodes
arguments exactly as the daemon does, which forced the rules to match both
forms — and caught the bug before deployment, not after.

**Two silent footguns in Wazuh itself:**

1. *Stock rules get there first.* Wazuh's built-in `0850-audit_rules.xml` already
   claims `python`, `scp`, `ps aux`, and `lscpu` audit events. My rules were
   being shadowed until I chained them off those stock IDs via `if_sid`.
2. *FIM `restrict` and escaped dots.* On 4.14.8, a `restrict` pattern written
   the "correct" regex way — `\.php$` — silently matches **nothing**, quietly
   disabling the whole FIM layer. Written unescaped — `.php$` — it works. If I
   had shipped the intuitive version, layer 3 would have been dead on arrival
   for anyone who copied it.

Neither is in the docs in a way that would have saved me. Both are now comments
in the shipped files. That is the difference between a rule pack you hope works
and one you have watched work.

The false-positive guards matter too. `rsync -e ssh` contains `-e`; `ssh -i`
contains `-i`. Neither is a reverse shell, and the tests assert they classify as
an ordinary shell spawn, not a critical alert. PHP activity and Node activity
are also checked never to cross-correlate into a false webshell alert.

Final result: **30/30**, reproducible with one command (`./tests/run.sh`),
against a clean container, in about a minute.

## Try it

The repo includes a self-contained lab — a deliberately vulnerable PHP app and
Node app behind nginx, a one-command victim setup, and a benign trigger script
that lights up each rule using only loopback-scoped commands. Stand it up on a
throwaway VM, point the agent at your manager, and watch
`rule.groups:web_to_shell` populate.

- Ruleset, lab, and tests: [link]
- Validated on Wazuh 4.14.8; stock decoders only, so it should hold across 4.x.

If you run a web stack on Wazuh, this is a high-value, low-noise detection to
add today — and a template for the broader principle: find the behaviour the
attacker can't avoid, key on it, and prove your rule before you trust it.
