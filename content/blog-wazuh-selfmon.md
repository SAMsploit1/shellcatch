# Everything said "active": making Wazuh notice when Wazuh is broken

*By [BYLINE: TBD] · Draft, November 2026*

The worst outage I've worked on didn't page anyone. On a production Wazuh
deployment, the OOM killer took `wazuh-db`, and the cgroup kill took the rest
of the manager with it: analysisd, remoted, logcollector, all of it. The
indexer stayed up. The dashboard stayed up. Filebeat stayed up. The manager's
systemd unit said `active`. For **59.5 hours** no event was analysed, and
nothing anywhere said so.

It wasn't the only one. On the same deployment:

- A watchdog built after that outage restarted the manager on schedule, raced
  a daemon that crashed during shutdown, and left `wazuh-db` dead. 15 of 16
  daemons were running and the unit said `active`. **99.5% of events were
  dropped for 5.5 hours.**
- The disk hit OpenSearch's flood-stage watermark. Every index went
  `read_only_allow_delete`, and ISM couldn't run the deletes that would have
  freed space. **Two days with no ingestion**, every service `active`, thousands
  of agents connected.
- analysisd's queues were saturated by a `wazuh-db` bottleneck. **About 83% of
  events had been dropped for months.** Indices kept growing, so ingestion
  looked fine.

The same two lessons came out of every one of them:

1. **A service reporting `active` proves nothing.**
2. **An alert that has to travel through the broken system never arrives.**

Wazuh is good at watching other systems. Out of the box it's poor at watching
itself, and that's an easy gap to fall into, because it's the system you'd use
to watch for the problem. This post is about the pack I built to close it,
[wazuh-selfmon](https://github.com/SAMsploit1/shellcatch/tree/master/detections/wazuh-selfmon),
and about the two systemd surprises I hit when I broke a lab manager on
purpose to prove it works.

## Why the obvious fix doesn't work

The obvious fix is the one I built first on that production box: a health
script that Wazuh runs itself, through a `<localfile>` block with
`<log_format>command</log_format>`, printing lines that custom rules turn into
alerts. It works well for a *sick* manager: full disks, saturated queues,
failed ISM steps.

It's useless for a *dead* one. The script runs inside the manager's own
logcollector. When the manager dies, the script dies with it, and even if it
didn't, its output would go to an analysisd that isn't running. That is
exactly why it didn't catch the 59.5-hour outage.

So the design rules for wazuh-selfmon came straight from the failures:

- **Run outside the manager.** A systemd timer of its own, not `Requires=` or
  `BindsTo=` on `wazuh-manager`, so it runs when the manager is gone.
- **Check processes, not units.** Find each `wazuh-*` daemon in `/proc`.
  (Read `cmdline`, not `comm`: `comm` is cut at 15 characters, so
  `wazuh-logcollector` shows up as `wazuh-logcollec`.)
- **Measure loss, not liveness.** Diff analysisd's `events_received` and
  `events_dropped` between runs. Read remoted's discards and the kernel's UDP
  `RcvbufErrors`, because syslog over UDP loses packets without a trace.
- **Test the whole pipeline end to end.** Don't infer that ingestion works
  from services being up.
- **Have a second way out.** Anything critical goes to a webhook directly, not
  only through Wazuh.

## The canary

That end-to-end check is the part I'd keep if I could keep only one.

Every run, the probe writes a heartbeat record to its log. A level-3 rule
matches it, which is deliberately high enough for it to be indexed. On the
next run the probe searches `wazuh-alerts-*` for that exact canary ID. If it
isn't there by the deadline, something between logcollector and the indexer is
broken.

The useful bit is the second question it asks: **did the canary reach
`alerts.json`?** If it did, the manager did its job and the break is
downstream, in filebeat or the indexer. If it didn't, the break is inside the
manager. So the alert names the stage:

> Wazuh pipeline stalled: canary not indexed. The manager wrote it to
> alerts.json, so the break is after the manager: filebeat or the indexer.

This is what catches the failure that's hardest to see. In the flood-stage
outage, filebeat was still running after the indexer recovered. It was
wedged, retrying, shipping nothing. Restarting it was what actually brought
ingestion back. A filebeat that's `active` and doing nothing passes every
liveness check there is. It doesn't pass this one.

## Surprise one: the stock unit can't tell you the manager is dead

To reproduce the OOM outage I SIGKILLed every process in the manager on a lab
running Wazuh 4.14.9:

```sh
systemctl kill -s KILL wazuh-manager
systemctl is-active wazuh-manager   # -> active
```

Every daemon gone, and the unit still said `active`. The reason is in the
stock unit file:

```ini
[Service]
Type=forking
ExecStart=/usr/bin/env /var/ossec/bin/wazuh-control start
KillMode=process
RemainAfterExit=yes
```

`wazuh-control start` launches the daemons and exits. With `Type=forking`
and no PID file, systemd has no main process to track (`MainPID=0`), and
`RemainAfterExit=yes` tells it to treat the unit as up regardless. It sits in
`active (exited)` whatever happens to the daemons.

The uncomfortable consequence: **`Restart=on-failure` can never fire on this
unit.** That was the top recommendation in my own incident write-up for the
59.5-hour outage, and it's the advice you'll find for "my service died and
didn't come back". Here it does nothing, because systemd never sees a
failure. My first draft of the pack included a `Restart=on-failure`
drop-in. I deleted it before publishing.

wazuh-selfmon doesn't care what the unit says. With every daemon missing it
reports:

> wazuh-manager is down: none of its daemons are running, yet the unit
> reports active.

The webhook got that 5 seconds after the kill.

## Surprise two: the watchdog that kills what it repairs

wazuh-selfmon can optionally repair a manager with missing daemons. It runs
`wazuh-control start`, which only starts what isn't running. That's
deliberate: a full restart is what hung on a crashing daemon in the 5.5-hour
outage.

The first test looked perfect. I killed `wazuh-db`, the probe ran
`wazuh-control start`, waited, saw `wazuh-db` running, and logged *"all
daemons are running again"*. Two minutes later the next run found `wazuh-db`
missing and repaired it again. The manager's log explained it:

```
13:19:12 wazuh-db: INFO: Started (pid: 16656).
13:19:25 wazuh-db: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
```

Thirteen seconds after starting, something sent `wazuh-db` a SIGTERM. That
something was systemd. The probe runs as a `Type=oneshot` service. Every
process it starts, including a daemon launched by `wazuh-control start`,
belongs to *the probe's* cgroup. When the oneshot exits, systemd cleans up its
cgroup and terminates whatever is left. The repaired daemon was killed by the
cleanup of the job that repaired it, after that job had already reported
success.

This trap applies to any watchdog run from a systemd service or timer that
restarts something by calling its start script directly, not just this one.
The fix is to put the repair command where systemd expects the daemons to be
before running it:

```sh
sh -c 'echo $$ > /sys/fs/cgroup/system.slice/wazuh-manager.service/cgroup.procs \
       && exec /var/ossec/bin/wazuh-control start'
```

After that, the restarted `wazuh-db` showed up in
`0::/system.slice/wazuh-manager.service`, was still alive 30 seconds later,
and the next run reported the recovery. If you run a home-grown Wazuh
watchdog from a timer, check this.

The pack also rate-limits repairs to three an hour, and a frequency rule
fires if that limit is reached. Something that keeps killing your manager is a
problem for a human, not for a restart loop. That rule fired for real during
testing, from the three "successful" repairs above.

## Getting alerts out of a dead system

Two pieces make sure the bad news arrives.

**Out-of-band.** Findings at or above a configurable severity are POSTed to a
webhook: ntfy, a Slack-compatible endpoint, anything that takes a POST. It
doesn't go through Wazuh, so it works when Wazuh doesn't. In the flood-stage
test this mattered more than I expected. Under `read_only_allow_delete` the
Wazuh alert *about* the write block can't be indexed either. Filebeat holds
it until the block lifts. The webhook had it in seconds.

**The backlog.** The probe writes to a plain JSON log, and the manager reads
it with:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/wazuh-selfmon/selfmon.json</location>
  <only-future-events>no</only-future-events>
</localfile>
```

`only-future-events no` makes logcollector read what was written while it was
down. So the record of the outage isn't lost. The probe wrote "manager is
down" at 13:21:39, the manager came back at 13:23:24, and the alert was in
`alerts.json` at 13:23:32 carrying the original `observed_at`. Your SIEM ends
up holding a record of its own outage, which helps when you have to write the
incident report.

For a host that's gone entirely, nothing on the host can help. Point
`HEARTBEAT_URL` at an external dead man's switch (healthchecks.io, Uptime
Kuma). The probe pings it after every run that found nothing critical.

## Breaking it on purpose

Every rule runs through the manager's own logtest socket in a 22-case suite
(22/22 on 4.14.9). That proves the rules match. It doesn't prove the probe
notices anything, so I broke a live 4.14.9 all-in-one on Azure seven ways:

| Fault injected | The unit said | What wazuh-selfmon reported |
|---|---|---|
| `kill -9` wazuh-db | `active` | 3 s: "unit active, daemons missing: wazuh-db" |
| SIGKILL every manager daemon | `active (exited)` | 5 s: "manager is down"; indexed 9 s after restart from the backlog |
| filebeat frozen with SIGSTOP | `active` | at the canary deadline: "break is after the manager: filebeat or the indexer" |
| flood-stage block (watermarks dropped to 20/25/30% at 31% disk) | n/a | 22 indices blocked in 25 s; CRITICAL out-of-band at once, Wazuh alert delivered once the block lifted |
| analysisd queue cut to 128, 11.6 M events in 60 s | `active` | "dropped 6,686,196 of 11,427,223 events (58.5%)" |
| 50,000 UDP datagrams into a 4 KB socket buffer | n/a | "kernel dropped 49,992 UDP datagrams" |
| ISM rollover with no `rollover_alias` | n/a | "1 indices have a failed ISM step; retention is not running" |

Each was detected, sent to the webhook, and reported again as RECOVERED when
I undid it. The probe only writes when a check changes state, plus an hourly
reminder while a problem lasts, so none of this is noisy when things are
healthy.

To reproduce the flood-stage outage I didn't fill the disk. I lowered the
watermarks below current usage with a transient cluster setting, then set them
back to `null`. OpenSearch released the block on its own five seconds later.
It's a safe way to rehearse the incident on any test cluster.

Two failures turned up that I didn't plan:

- **The canary caught my own bug.** My first ruleset had the canary rule
  shadowed by the generic "check OK" rule, a sibling-ordering mistake, so
  canaries matched at level 0 and were never indexed. The next run reported
  that the canary *"never reached alerts.json … or the rule is not loaded"*.
  It was right.
- **`unattended-upgrades` restarted the manager mid-test.** The lab's first
  boot in three days pulled a zlib security update, and `needrestart`
  restarted every service linked against libz, `wazuh-manager` included. On a
  production manager you probably want a person to make that decision:
  exclude them in needrestart with
  `$nrconf{override_rc}{qr(^wazuh-)} = 0;` in `/etc/needrestart/conf.d/`.

## What it doesn't do

- **It can't report a dead host.** That needs the external heartbeat.
- **It's 4.x only.** Wazuh 5.0 replaces analysisd with the new engine, and
  the counters are different.
- **It watches one node.** In a manager cluster, run it on every node.
- **It never restarts a running manager because of memory.** It alerts on
  wazuh-db RSS, but a manager whose wazuh-db keeps growing needs someone to
  find out why. Restarting it on a threshold is how the 5.5-hour outage
  started.

## Try it

On a Wazuh 4.x manager, as root:

```sh
git clone https://github.com/SAMsploit1/shellcatch
cd shellcatch/detections/wazuh-selfmon
sh install.sh
```

The installer checks for rule-ID clashes, validates the ruleset with
`wazuh-analysisd -t`, adds the `<localfile>` block (backing up `ossec.conf`),
enables the timer and prints a dry run of every check. Then set `NOTIFY_URL`
in `/etc/wazuh-selfmon.conf`. Without it, a dead manager still has no way to
tell you.

The probe is a single Python file using only the standard library. Read it
before you run it as root on your SIEM. That's good advice for any pack,
including this one.
