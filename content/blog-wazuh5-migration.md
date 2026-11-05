# Bringing a real detection pack to Wazuh 5.0: a complete, tested migration

*By SAMspl0it — Wazuh Ambassador · 5 November 2026 · tested on Wazuh 5.0.0-rc2*

Wazuh 5.0 changes how detection content works. The manager no longer matches
XML rules. Its engine normalizes every event into the Wazuh Common Schema
(WCS) and indexes it, and detectors in the indexer run Sigma rules over those
indices and write *findings*. Rules live in the indexer, are managed through
an API, and move through Draft → Test → Custom spaces instead of being files
you copy and restart for.

Wazuh's [rule migration guide](https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/docs/guide/migration/rules-4x-to-5x.md)
covers the mechanics. This post is the worked example: a complete community
pack, [shellcatch](https://github.com/SAMsploit1/shellcatch) (web-to-shell
detection for PHP and Node.js, 19 XML rules across auditd, access logs and
FIM), migrated end to end on a live 5.0.0-rc2 lab, with real events, real
findings, and the correlation rebuilt. Everything here was run, and the
repository has the rules, the monitors, the test suite and the tooling.

If you maintain custom 4.x rules, this is roughly the path you'll walk.

## The lab

Two VMs on Azure: a 5.0.0-rc2 all-in-one (`wazuh-install-5.0.0-rc2.sh -a -d
pre-release`, about eight minutes), and an Ubuntu 24.04 victim running the
pack's deliberately vulnerable nginx + PHP-FPM + Node.js apps, auditd, and a
5.0 agent. The victim has no public address. Two first-contact notes:

- **Agents enroll with a token now.** `WAZUH_MANAGER` is ignored. Mint a token
  on the manager with `wazuh-manager-authd --create-enrollment-token --address
  <manager>` and feed it to `wazuh-agent-auth` on the agent.
- **Standard content arrives from CTI on first boot.** On this install it was
  127 integrations, 517 decoders and 369 rules, synced within a few minutes.

## Step 1: look at your events before you write a rule

The single most useful habit in 5.0: send real traffic, then read the
normalized event. Rule fields are validated against the WCS when you create
the rule, so you can't guess.

A PHP webshell running `base64 -d` came out of the standard `auditd`
integration like this (trimmed):

```json
"process": {
  "name": "base64", "executable": "/usr/bin/base64",
  "command_line": "base64 -d", "args": ["base64", "-d"],
  "working_directory": "/var/www/html", "parent": {"pid": 12657}
},
"user": {"effective": {"id": "33", "name": "www-data"}},
"rule": {"name": "web_exec_php"},
"event": {"action": "started", "category": ["process"], "outcome": "success"}
```

Three things worth celebrating here, because they delete work:

1. **`process.command_line` is rebuilt from the EXECVE record.** auditd
   hex-encodes any argument with a space or a quote, so the 4.x pack matched
   alternations like `62617368202D69` (`bash -i`). In 5.0 that's just
   `bash -i`.
2. **The euid is resolved to a name.** `user.effective.name: www-data`.
3. **The audit key lands in `rule.name`**, the ECS convention. That's the
   field every exec rule keys on.

Access logs came out of the standard `apache-http` integration (it decodes
nginx's combined format too) with `url.original`, `url.path`, `url.query`,
`url.extension` and `http.response.status_code`. FIM events came from
`wazuh-fim` with `file.path`, `file.extension` and `event.action:
created|modified|deleted`.

One more check worth doing: what does the standard content already catch? Over
every attack run in this lab, the standard rules raised a `low` "File created"
finding for each dropped file, and one access-log rule ("Windows webshell
strings") matched a `?cmd=whoami` request. None of the 41 standard auditd rules
flagged `www-data` running `id`, `curl`, `nc -e` or `base64 -d`. Good
foundations, and still a clear job for a pack like this in 5.0.

## Step 2: decide where the rules live

Custom rules can't be attached to standard integrations, so you create your
own. The question is whether it needs decoders. Here it doesn't: the standard
`windows-rules` integration, described as "an extension of the rules under the
windows integration", ships rules and no decoders, and it works the same way
for custom content. So `web-to-shell` is a rules-only integration over events
other integrations already normalized.

The events sit in two indices (auditd and FIM in
`wazuh-events-v5-system-activity`, access logs in
`wazuh-events-v5-applications`), and a detector can read several. The standard
`wazuh-generic-1` detector covers all seven. One detector over two indices
does it.

## Step 3: rewrite the rules

The migration guide's mapping tables do most of the translation. What took
thought was what they imply.

**Grouping rules disappear.** 100500/100501 existed only to bind children to
the audit key with `if_sid`. Each 5.0 rule carries that condition itself:

```yaml
web_exec:
  wazuh.integration.name: auditd
  event.action: started
  rule.name: [web_exec_php, web_exec_node]
discovery:
  process.name: [id, whoami, uname, hostname, ip, ss, ps, getent, lscpu]
condition: web_exec and discovery
```

**Precedence becomes your job.** In 4.x an event raised one alert: the first
matching child won. In 5.0 every rule sees every event, and each match is its
own finding. `sh -c '… | base64 -d | sh'` would be both "base64-decoded
command line" (high) and "shell spawned" (medium). To keep one finding per
event, lower rules exclude what higher rules cover:

```yaml
condition: web_exec and shell and not payload
```

The upside: 4.x's rule-ordering quirks go away. The access-log rules no longer
need to chain off stock 31104/31106/31108 just because those claimed the event
first.

**Allowlist children become filters.** PHP's `mail()` runs `sh -c`, and every
contact form would raise a shell-spawn alert. In 4.x a level-3 child matched
the hex-encoded sendmail argument. I captured what 5.0 actually sees for PHP
8.3:

```
sh -c -- /usr/sbin/sendmail -t -i
sh -c -- /usr/sbin/sendmail -t -i -fnoreply@example.com
```

and the filter allows those exactly, unless a shell metacharacter follows, so
an injected `-fx@example.com;id` still alerts.

**Titles take placeholders.** `$(audit.exe)` in a 4.x description is
`{{process.name}}` in a 5.0 title, so findings read *"Web-to-shell: discovery
command whoami launched by web runtime"*. The standard rules do the same.

The result: the 19 XML rules became 15 Sigma rules and one monitor. The two
grouping rules and the `mail()` child fold into conditions, and the frequency
rule becomes a monitor (step 7). Each rule file notes the 4.x rule it replaces.

## Step 4: test with the events you captured

5.0 has a detection-only logtest that takes an already-normalized event:

```
POST /_plugins/_content_manager/logtest/detection
{"space": "test", "integration": "<id>", "input": { …normalized event… }}
```

That makes a clean test harness. A driver script on the victim produces one
real event per case (all benign, loopback-only), a capture step saves the
newest matching event from the index as a fixture, with the raw log and agent
identity stripped, and the test step replays each fixture and compares the
**exact set** of matching rules with the expected one. Exact matters, because
of the precedence point above: an overlap between rules is a failure, not a
bonus.

26 cases, 8 of them negative (PHP `mail()`, a benign request, the app's own
`ping`, modified and deleted files). The fixtures are in the repo, so anyone
can run the suite against their own 5.0 install without a victim host.

The first run was 24/26, and the two failures were the most useful result of
the whole migration.

## Step 5: three things the rc2 backend does differently

These are 5.0.0-rc2 behaviours, not design decisions, and I expect them to be
fixed. Each was reproduced on the live detector with a probe rule and a
control rule, and the compiled query is right there in the indexer to read
(`.opensearch-sap-custom-rules-config`). That transparency made each one quick
to diagnose.

**A `|re` containing `/` never matches.** Sigma regex compiles to a Lucene
query-string regex, `field: /.*(X).*/`, and `/` isn't escaped:

```
process.executable|re: "/usr/bin/id$"  ->  process.executable: /.*(/usr/bin/id)/   # never matches
process.executable|re: "bin.id$"       ->  process.executable: /.*(bin.id)/        # matches
```

None of the 368 standard rules put a slash in a regex; most Linux path rules
will. Until it's fixed, use `endswith`/`contains`/`startswith` lists for paths
(which is what the migration guide recommends anyway) and keep `|re` for
patterns like `process.name|re: "^(python[0-9.]*|perl[0-9.]*)$"`.

**A `not` nested inside a negated group is lost.** That's what the two failing
cases caught. The natural allowlist condition:

```
shell and not (php_mail_sender and not metachar)
```

compiles to `... ((NOT sender) OR (NOT NOT metachar))`, and Lucene doesn't read
`NOT NOT` as a double negation, so the clause never matches: the clean
`mail()` call alerted, and the injected one didn't. Writing the condition
already expanded with De Morgan's law is equivalent and compiles correctly:

```
shell and (not php_mail_sender or metachar)
```

**`|re|i` is documented but rejected** (`Unknown modifier i`). Matching is
case-sensitive everywhere, so spell it out where it matters:
`[pP][hH][pP]`.

All three have short, specific fixes in the backend. The reproductions,
compiled queries and suggested patches are written up in the repository
([upstream/issues-5.0-rc2-sigma-backend.md](https://github.com/SAMsploit1/shellcatch/blob/master/upstream/issues-5.0-rc2-sigma-backend.md))
for the Wazuh team.

After the rewrite: 26/26.

## Step 6: deploy for real

Promote Test → Custom and create a detector for the custom rules over both
indices (a custom integration doesn't get one automatically). Detector input
`custom_rules` takes the Content Manager document IDs of the custom-space
rules. Then run the attack again.

Every one of the 15 rules produced its finding on the live detector, with the
title rendered and the pack's own tags carried into `wazuh.rule.tags`. Every
negative stayed silent. auditd findings showed up within a minute or two;
access-log and FIM findings took a few minutes longer on this single node.

## Step 7: rebuild the correlation

5.0 rules have no `frequency`, `if_matched_*`, `same_*`, `different_*` or
`if_fts`, and 5.0.0 ships no correlation rules; Sigma correlation is
[planned](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/119).
The migration guide shows the answer for counting: a bucket-level monitor from
the Alerting plugin over the findings indices. The same tool covers more than
counting, which is the part I most wanted to show:

| 4.x construct | Monitor | Logic |
|---|---|---|
| `frequency` + `if_matched_group` + `same_field` | interactive webshell | composite by agent + account; `_count >= 3` in 5 min |
| `different_url` | path probing | per `source.ip`: `cardinality(url.path) >= 3` |
| `if_fts` | first-seen exec | per agent + executable over 7 days of *events*: hits in the last 2 min, none before |
| *(ordered sequence)* | drop then exec | per agent: `min(@timestamp)` of drop findings `<` `max(@timestamp)` of exec findings |

The trick that makes most of these work is a `filter` sub-aggregation per
condition inside the composite bucket, compared in the trigger script:

```json
"aggregations": {
  "drop": {"filter": {"term": {"wazuh.rule.tags": "shellcatch.drop"}},
           "aggregations": {"first": {"min": {"field": "@timestamp"}}}},
  "exec": {"filter": {"terms": {"wazuh.rule.tags": ["shellcatch.activity", "shellcatch.spawn"]}},
           "aggregations": {"last": {"max": {"field": "@timestamp"}}}}
}
...
"buckets_path": {"drops": "drop>_count", "execs": "exec>_count",
                 "drop_first": "drop>first", "exec_last": "exec>last"},
"script": "params.drops > 0 && params.execs > 0 && params.exec_last > params.drop_first"
```

The drop-then-exec sequence is something 4.x couldn't express cleanly at all.
`if_matched_sid` only knows that a match happened earlier, not across sources
in order.

Then the end-to-end test: upload a three-line lab webshell through the
vulnerable form, call it with `id`, `whoami`, `lscpu`, and probe a few other
webshell names. All four monitors raised alerts, each with the right bucket
keys (agent `001`; `001`/`www-data`; `127.0.0.1`; `001`/`/usr/bin/lscpu`),
within two minutes of the upload.

Two design notes. Windows are five minutes where 4.x used two, because
detectors run every one to two minutes and stamp findings with the event time,
so a short window can close before its findings arrive (the migration guide
makes the same point). And monitor alerts live in *Alerting > Alerts* and can
notify a channel; they're a different object from findings.

## What I'd tell someone starting their own migration

- **Capture first, write second.** Ten minutes of real traffic and a look at
  the normalized events beats any amount of guessing at field names.
- **Expect deletions.** Hex decoding, grouping rules and stock-rule chaining
  workarounds all went away here. The 5.0 rules are shorter than the XML.
- **Test exact sets of findings,** including negatives. That's how both rc2
  backend issues surfaced, and it's what catches rule overlap.
- **Read the compiled query when a rule surprises you.** It's in the indexer.
- **Correlation is a monitor today,** and monitors can do more than counting.

The rules, monitors, fixtures, test suite, lab and `w2s.py` (deploy, promote,
test, detector, monitors) are in the repository under
[`detections/web-to-shell/wazuh5`](https://github.com/SAMsploit1/shellcatch/tree/master/detections/web-to-shell/wazuh5).
Wazuh 5.0 is the biggest change to Wazuh content in years, and having done a
full migration, it's a good one: the normalized events are better, the rules
are clearer, and the API-driven lifecycle with a real test space is something
4.x never had.

> **Lab warning.** The victim apps are exploitable by design. Run them only on
> a throwaway VM in an isolated network, never internet-facing, and never
> enrolled on a manager that serves production agents.
