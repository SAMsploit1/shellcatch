# wazuh-selfmon: make Wazuh notice when Wazuh is broken

A self-monitoring pack for Wazuh 4.x managers. It catches the failures where
every dashboard looks fine and no events are being processed, and it reports
them even when the failure is Wazuh itself.

Every check here comes from a real outage on a production deployment of
several thousand agents. Each one went unnoticed for hours or days:

| What happened | How long it went unnoticed | Why nothing alerted |
|---|---|---|
| wazuh-db leaked memory, the OOM killer took it, the cgroup kill took the rest of the manager | 59.5 h | Indexer, dashboard and filebeat stayed up. The unit stayed "active". Wazuh can't alert about Wazuh being dead. |
| A watchdog's own restart raced a crashing daemon; wazuh-db never came back | 5.5 h, 99.5% of events dropped | 15 of 16 daemons running and the unit "active" |
| Disk hit the flood-stage watermark; every index went `read_only_allow_delete`; ISM couldn't delete anything to free space | 2 days, no ingestion | Every service "active", 8,500 agents connected |
| analysisd's queues were saturated by a wazuh-db bottleneck | months, ~83% of events dropped | Indices kept growing, so ingestion looked healthy |

The lesson behind all four: **a service reporting `active` proves nothing**,
and **an alert that has to pass through the broken system never arrives.**

## What it does

`wazuh-selfmon` is a small Python program (standard library only) run by its
**own systemd timer**, outside the manager's process tree. Every 2 minutes it:

1. **Checks processes, not units.** It finds each expected `wazuh-*` daemon in
   `/proc`, flags any that are missing while the unit says `active`, and reads
   wazuh-db's RSS.
2. **Measures loss.** It diffs analysisd's `events_received` and `events_dropped`
   against the same analysisd PID between runs, reads queue saturation, remoted
   discards, and the kernel's UDP `RcvbufErrors` (syslog over UDP drops silently).
3. **Checks the indexer.** Cluster health, disk use against *the cluster's own*
   watermarks (custom ones included), `read_only_allow_delete` blocks, failed
   ISM steps, and whether filebeat is running.
4. **Sends a canary through the whole pipeline.** Each run writes a heartbeat
   record. The next run looks it up in `wazuh-alerts-*`. If it's missing, the
   probe checks `alerts.json` to say where it stopped: *inside the manager*
   (logcollector/analysisd) or *after it* (filebeat/indexer). This is what
   catches a filebeat that's running but wedged.
5. **Reports through two channels.** Findings go to a JSON log that the manager
   ingests (rules 100800-100819). CRITICAL findings also go **out-of-band** to a
   webhook (ntfy, Slack-compatible, anything that accepts a POST), because a
   dead manager can't raise an alert about itself. An optional dead man's
   switch URL covers a host that's gone entirely.
6. **Can repair (optional).** If daemons are missing it runs `wazuh-control
   start`, which starts only what's missing, rather than a full restart that
   can hang on a daemon crashing during shutdown. Repairs are rate-limited
   (3/hour), and rule 100818 fires if the limit is reached.

It only writes when a check **changes state**, plus an hourly reminder while a
problem lasts. Every recovery is reported.

### Things learned building it (all verified in the lab below)

- **The stock `wazuh-manager.service` can't tell you the manager is dead.**
  It's `Type=forking` with `RemainAfterExit=yes`, so systemd tracks no process
  (`MainPID=0`, `active (exited)`). With every manager process SIGKILLed it
  still reports `active`. That also means **`Restart=on-failure` can never
  trigger**: adding it, the usual advice, does nothing on this unit.
- **A watchdog that repairs from its own systemd unit kills what it repairs.**
  Whatever `wazuh-control start` launches from inside a oneshot service lands
  in that service's cgroup. When the oneshot exits, systemd SIGTERMs the
  cgroup: the restarted wazuh-db died 13 s later, after the watchdog had
  already logged success. wazuh-selfmon moves the repair command into
  `wazuh-manager.service`'s cgroup first.
- **Alerts written while the manager is down aren't lost** if the log is read
  with `<only-future-events>no</only-future-events>`. Logcollector picks up the
  backlog on restart, and the "manager was down" alert lands seconds after
  recovery with the original `observed_at`.
- **Under a flood-stage block the alert about the block can't be indexed.**
  Filebeat holds it and delivers it once the block lifts. That's fine for the
  record, and it's why the out-of-band channel exists.
- **`unattended-upgrades` restarts the manager.** A routine zlib security
  update had `needrestart` restart every service linked to libz, wazuh-manager
  included, in the middle of a test run. Consider holding Wazuh services in
  needrestart's config on production managers.

## Install

On the manager, as root:

```sh
git clone https://github.com/SAMsploit1/shellcatch && cd shellcatch/detections/wazuh-selfmon
sh install.sh
```

`install.sh` installs the probe to `/usr/local/sbin`, the config to
`/etc/wazuh-selfmon.conf` (kept if present), the rules, the `<localfile>`
block (backing up `ossec.conf`) and the timer. It checks for rule-ID clashes,
validates the ruleset with `wazuh-analysisd -t`, restarts the manager and
prints a dry run.

Then set at least `NOTIFY_URL` in `/etc/wazuh-selfmon.conf`. Every key is
documented in [config/wazuh-selfmon.conf](config/wazuh-selfmon.conf).

**Notes**
- The default indexer access uses the all-in-one admin client certificate in
  `/etc/wazuh-indexer/certs/`. On a distributed install set `INDEXER_URL` and
  either copy a client cert or set `INDEXER_USER`/`INDEXER_PASS`. The user needs
  `cluster:monitor/*`, index settings read, ISM explain, and search on
  `wazuh-alerts-*`.
- Size `WDB_RSS_*_MB` to your RAM. The defaults suit a 16-32 GB manager.
- Cluster nodes: add `wazuh-clusterd` to `EXPECTED_DAEMONS`.
- Single-node all-in-one: OpenSearch system indices created later (ISM,
  job-scheduler) default to 1 replica, which can't be assigned on one node, so
  health goes yellow (WARN). Set their `number_of_replicas` to 0 with the admin
  cert, or accept the warning.
- On a busy manager the canary depends on `wazuh-alerts-*` being searchable
  within `CANARY_MAX_AGE` (default 600 s). Raise it if filebeat routinely lags.

## Rules (100800-100819)

| ID | Level | Fires on |
|---|---|---|
| 100800 | 0 | any selfmon record (base) |
| 100801 | 3 | canary heartbeat: indexed on purpose, so it can be looked up |
| 100802 | 0 | a check is OK |
| 100803 | 5 | a check recovered |
| 100804 / 100805 / 100806 | 7 / 10 / 13 | generic WARN / HIGH / CRITICAL |
| 100810 | 13 | unit active, daemons missing (T1562.001: also how a defender-killing intruder looks) |
| 100811 | 13 | manager unit not active (with the stock unit this rarely fires: see above) |
| 100812 | 10 | pipeline stalled: canary not indexed, with the stage |
| 100813 | 13 | indexer write block (flood-stage watermark) |
| 100814 | 10 | analysisd dropping events |
| 100815 | 10 | UDP receive-buffer loss |
| 100816 | 10 | wazuh-db memory high/critical |
| 100817 | 7 | the probe repaired the manager |
| 100818 | 12 | 3 repairs in an hour |

## Tests

**Rule tests:** `tests/run_tests.py` sends 22 cases through the manager's own
logtest socket, covering every rule, the tier boundaries, a negative case and
the 3-in-an-hour frequency rule. **22/22 pass** on Wazuh 4.14.9.

```sh
sudo python3 -I tests/run_tests.py
```

**Fault injection:** every failure mode was reproduced on a live Wazuh 4.14.9
all-in-one (Azure, Ubuntu 24.04, 4 vCPU/16 GB). Times are UTC on 2026-11-06.

| # | Fault injected | Unit said | Detected | Out-of-band | Recovery reported |
|---|---|---|---|---|---|
| 1 | `kill -9` wazuh-db | `active` | 3 s: 100810 "daemons missing: wazuh-db" | 3 s | yes |
| 1b | same, with `REMEDIATE=yes` | `active` | repaired in 17 s; daemon in `wazuh-manager.service` cgroup and still alive 30 s later | yes | yes |
| 2 | `systemctl kill -s KILL wazuh-manager` (OOM-style kill of every daemon) | `active (exited)` | 5 s: CRITICAL "none of its daemons are running" | 5 s | the alert written at 13:21:39 while the manager was dead was indexed 9 s after restart |
| 3 | filebeat frozen with `SIGSTOP` (wedged, not stopped) | `active` | at the 4-min canary deadline: 100812 "the manager wrote it to alerts.json, so the break is after the manager: filebeat or the indexer" | yes | 2 min after `SIGCONT` |
| 3b | filebeat stopped | `inactive` | next run: CRITICAL filebeat.unit | yes | yes |
| 4 | flood stage: watermarks set to 20/25/30% at 31% disk | n/a | 22 indices blocked in 25 s; 100813 + indexer.disk CRITICAL | yes (the Wazuh alert itself was held by filebeat until the block lifted) | block auto-released 5 s after reset; recovery reported |
| 5 | analysisd decode queue cut to 128, 11.6 M events in 60 s | `active` | 100814 "dropped 6,686,196 of 11,427,223 (58.5%)", queue at 100% | yes | yes |
| 6 | 50,000 UDP datagrams into a 4 KB socket buffer | n/a | 100815 "kernel dropped 49,992 UDP datagrams" | yes | yes |
| 7 | ISM policy with a rollover and no `rollover_alias` | n/a | 100805 indexer.ism "1 indices have a failed ISM step" | yes | yes |

Two unplanned true positives turned up as well. A canary written while its
rule was mis-ordered was correctly reported as "never reached alerts.json …
or the rule is not loaded". The manager restart caused by unattended-upgrades
was picked up too.

## Files

```
probe/wazuh-selfmon            the probe (Python 3, stdlib only)
rules/wazuh_selfmon_rules.xml  rules 100800-100819
config/wazuh-selfmon.conf      every setting, with defaults
config/ossec.conf.snippet      the <localfile> block
systemd/                       service + 2-minute timer
install.sh                     installer
tests/run_tests.py, cases.json logtest suite
```

## Limits

- It runs on the manager host, so it can't report a dead *host*. Use
  `HEARTBEAT_URL` with an external dead man's switch (healthchecks.io, Uptime
  Kuma, Cronitor) for that.
- Wazuh 4.x only. 5.0 replaces analysisd with the new engine, and the
  counters differ.
- It watches the manager node it runs on plus the indexer cluster it can
  reach. In a manager cluster, run it on every node.
- Remediation only starts missing daemons or a stopped manager. It never
  restarts a running one because of memory. That decision belongs to a human
  who knows why wazuh-db is growing.

License: GPLv2.
