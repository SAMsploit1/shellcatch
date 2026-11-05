# web-to-shell for Wazuh 5.0

The [4.x pack](../README.md) migrated to the Wazuh 5.0 content model: Sigma
rules in a custom integration, managed through the Content Manager API, with
the 4.x correlation rebuilt as Alerting monitors. Same detections, same three
layers, tested against real events from a live 5.0 lab.

**Tested on:** Wazuh 5.0.0-rc2 all-in-one (manager, indexer, dashboard) and a
5.0.0-rc2 agent on Ubuntu 24.04, nginx + PHP 8.3-FPM + Node.js 18. 5.0 is not
GA yet: re-check the [known issues](#known-issues-on-500-rc2) on later builds.

```
wazuh5/
├── rules/         15 Sigma rules (one file per rule, each says which 4.x rule it replaces)
├── monitors/      4 correlation monitors (Alerting bucket-level monitors)
├── tools/w2s.py   deploy, promote, test, detector, monitors (stdlib + PyYAML)
└── tests/
    ├── cases.json      26 cases: expected findings per event (8 are negatives)
    ├── fixtures/       26 normalized events captured from the live lab
    ├── drive.sh        produces those events on the lab victim
    └── attack-sequence.sh  end-to-end scenario for the monitors
```

## How it fits the 5.0 model

In 5.0 the manager no longer evaluates rules. The engine decodes and
normalizes events into the Wazuh Common Schema (WCS) and indexes them;
detectors in the indexer run Sigma rules over those indices and write
*findings*. Custom rules can't be attached to the standard integrations, so
the pack is its own integration, `web-to-shell`, with **no decoders**: it reads
events that the standard `auditd`, `wazuh-fim` and `apache-http` integrations
already normalized (the same pattern as the standard `windows-rules`
integration). One detector covers both indices those events land in.

| Layer | Events from | Event index | Rules |
|---|---|---|---|
| Process execution | `auditd` (with the [auditd rules](../auditd/60-web-to-shell.rules)) | `wazuh-events-v5-system-activity` | 9 |
| Web requests | `apache-http` (it also decodes nginx's combined format) | `wazuh-events-v5-applications` | 3 |
| File integrity | `wazuh-fim` | `wazuh-events-v5-system-activity` | 3 |

## Install

On each web server: load the auditd rules and merge the agent config exactly
as in the [4.x INSTALL](../INSTALL.md). Two 5.0 differences:

- The agent enrolls with a token, not `WAZUH_MANAGER`. On the manager:
  `sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <manager>`,
  then on the agent: `echo '<token>' | sudo /var/ossec/bin/wazuh-agent-auth`.
- The 5.0 agent's default config already reads `/var/log/audit/audit.log` and
  the nginx access log; the duplicate `<localfile>` warnings on start are
  harmless.

On the manager (or any host that reaches the indexer), from `tools/`:

```bash
sudo python3 w2s.py deploy ../rules            # draft: integration + 15 rules, then promote to test
sudo python3 w2s.py test ../tests/cases.json   # 26/26 expected
sudo python3 w2s.py promote test               # test -> custom (production)
sudo python3 w2s.py detector                   # detector over both event indices
sudo python3 w2s.py monitors ../monitors       # correlation monitors
```

`w2s.py` reads the indexer admin password from
`/etc/wazuh-indexer/export/credentials.env` (or `WAZUH_INDEXER_ADMIN_PASSWORD`).
Set `WAZUH_INDEXER_CA` to verify TLS; without it, the lab default skips
verification for the installer's self-signed certificates.

## 4.x → 5.0 rule map

| 4.x | Level | 5.0 rule file | Level |
|---|---|---|---|
| 100500, 100501 | 3 | *(gone: grouping rules; their condition is the `web_exec` selection in every exec rule)* | |
| 100530 | 15 | `exec-reverse-shell.yml` | critical |
| 100531 | 15 | `exec-netcat-exec-flag.yml` | critical |
| 100541 | 12 | `exec-base64-command-line.yml` | high |
| 100540 | 12 | `exec-base64-binary.yml` | high |
| 100521 | 12 | `exec-network-tool.yml` | high |
| 100520 | 12 | `exec-discovery.yml` | high |
| 100523 | 12 | `exec-inline-code.yml` | high |
| 100522 | 10 | `exec-script-interpreter.yml` | high |
| 100510 + 100511 | 8 / 3 | `exec-shell-spawn.yml` (the mail() child becomes a filter) | medium |
| 100550 | 14 | `monitors/interactive-webshell.json` | monitor, severity 1 |
| 100560 | 12 | `web-command-payload.yml` | high |
| 100561 | 10 | `web-upload-dir-php.yml` | high |
| 100562 | 6 | `web-command-parameter.yml` | low |
| 100570 | 10 | `fim-php-in-webroot.yml` | high |
| 100571 | 12 | `fim-php-exec-config.yml` | high |
| 100572 | 10 | `fim-js-in-node-app.yml` | high |
| *(new)* | | `monitors/drop-then-exec.json`, `path-probing.json`, `first-seen-exec.json` | monitors |

Levels follow the mapping table in Wazuh's migration guide.

## What changed, and why

**The hex workarounds are gone.** auditd hex-encodes any argument with a space
or quote, so the 4.x rules carried alternations like `62617368202D69`
(`bash -i`). The 5.0 auditd decoder rebuilds `process.command_line` and
`process.args` from the EXECVE record and resolves the euid to
`user.effective.name`, so the rules match plain text. The audit key lands in
`rule.name` (the ECS convention), which is what every exec rule keys on.

**`if_sid` chains are flattened.** Rules 100500/100501 existed only to bind
children to the audit key. In 5.0 each rule carries that condition itself:

```yaml
web_exec:
  wazuh.integration.name: auditd
  event.action: started
  rule.name: [web_exec_php, web_exec_node]
```

**Precedence becomes explicit.** In 4.x one event raised one alert: the first
matching child in rule order won, so `sh -c '…| base64 -d | sh'` alerted as
base64 and not also as a shell spawn. 5.0 evaluates every rule on every event,
so the same event produces one finding *per matching rule*. To keep one finding
per event, the lower rules exclude what the higher ones cover (`and not
payload`, `and not inline`). The test cases assert the exact set of findings
for each event, so an overlap shows up as a failure.

**The stock-rule shadowing is gone too.** In 4.x the access-log rules had to
hang off stock 31104/31106/31108 because those claimed the event first. Sigma
rules don't compete, so that workaround disappears.

**Titles take placeholders.** 4.x `$(audit.exe)` in a description is
`{{process.executable}}` in a 5.0 title, so a finding reads
`Web-to-shell: discovery command id launched by web runtime`.

**FIM rules key on `event.action`.** Stock 554 (file added) is
`event.action: created` from the `wazuh-fim` integration; 550 (changed) is
`modified`. The stock `wazuh-fim` integration already raises a `low` "File
created" finding for every monitored path, so these rules rank web code higher
rather than adding first coverage.

## Correlation: rebuilding what 5.0 dropped

5.0 rules have no `frequency`, `timeframe`, `if_matched_*`, `same_*`,
`different_*` or `if_fts`, and 5.0.0 ships no correlation rules (Sigma
correlation is planned in
[wazuh-indexer-security-analytics#119](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/119)).
Wazuh's migration guide shows a bucket-level monitor for the simple count case.
The four monitors here extend that to the other patterns, all over the
findings indices, keyed on the pack's `shellcatch.*` tags (custom tags are
carried into `wazuh.rule.tags`):

| Monitor | Replaces | How |
|---|---|---|
| `interactive-webshell` | 100550: `frequency=3`, `if_matched_group`, `same_field` | composite by agent + `user.effective.name`, `_count >= 3` in 5 min |
| `drop-then-exec` | an ordered sequence (no 4.x equivalent) | per agent: `min(@timestamp)` of drop findings `<` `max(@timestamp)` of exec findings, 10 min |
| `path-probing` | `different_url` | per `source.ip`: `cardinality(url.path) >= 3` in 10 min |
| `first-seen-exec` | `if_fts` | per agent + `process.executable` over 7 days of events: hits in the last 2 min and none before |

Two things to know about all of them:

- **Windows are longer than in 4.x.** Detectors run every 1–2 minutes and stamp
  findings with the event's time, so a finding can land after a short window
  has already closed. 5 minutes where 4.x used 2.
- **They raise Alerting alerts, not findings.** Monitor alerts live in
  *Alerting > Alerts* (and can notify a channel); they don't appear next to
  findings in the threat-hunting views.

## Testing

`w2s.py test` replays each fixture through
`POST /_plugins/_content_manager/logtest/detection` against the test space and
compares the exact list of matching rules with `cases.json`. Fixtures are real
normalized events from the lab (raw log and agent identity stripped), so the
suite runs without a victim host. `drive.sh` regenerates them and `w2s.py
capture` saves the newest live event per case.

The same events were also sent through the live detector: every rule produced
its finding, and the negative cases (PHP `mail()`, a benign request, the app's
own `ping`, a modified or deleted file) produced none. `attack-sequence.sh`
(upload a webshell, then use it) raised all four monitor alerts, with the
right bucket keys, within two minutes of the upload.

## Known issues on 5.0.0-rc2

Three behaviours of the Sigma backend shaped how these rules are written. Each
was reproduced on the live detector path with a probe rule and a control rule,
not only through logtest. The compiled queries below are read from
`.opensearch-sap-custom-rules-config`.

**1. A `|re` value containing `/` never matches.** `field|re: X` compiles to
the Lucene query-string form `field: /.*(X).*/` and only `"` and `\` are
escaped, so the first `/` in a path closes the regex:

```
process.executable|re: "/usr/bin/id$"  ->  process.executable: /.*(/usr/bin/id)/   # 0 findings
process.executable|re: "bin.id$"       ->  process.executable: /.*(bin.id)/        # matches
```

Writing `\/` doesn't help, because the backslash is escaped too. Workaround
used here: `endswith`/`contains`/`startswith` lists or exact-name lists for
anything with a path in it, and `|re` only for patterns without `/` (e.g.
`process.name|re: "^(python[0-9.]*|perl[0-9.]*)$"`). None of the 368 standard
rules put a `/` in a regex, which is probably why it hasn't come up; most
Linux path matching will. Also avoid `&` in a `|re`: Lucene regex treats it
as an operator.

**2. A `not` nested inside a negated group is lost.** The backend pushes a
group's negation down with De Morgan's law, and a `not` it meets on the way
gets a second `NOT` instead of cancelling:

```
sh and not (s and not m)   ->  ... AND ((NOT s) OR (NOT NOT m))   # 0 findings, ever
sh and (not s or m)        ->  ... AND ((NOT s) OR m)             # correct
```

Lucene's query-string parser doesn't read `NOT NOT m` as `m`, so the clause
never matches, and the detection fails silently. Workaround: write the
condition already expanded, as `exec-shell-spawn.yml` does. The test case
`exec_php_mail_injected` caught this one.

**3. The `|re|i`, `|re|m` and `|re|s` flags are documented but not
implemented.** Both Wazuh's migration guide and the indexer's rules reference
list them; rc2 rejects the rule with `Unknown modifier i` (no flag modifiers
are registered in `SigmaModifierFacade`). Workaround: spell case-insensitivity
with character classes (`[pP][hH][pP]`), as the access-log and FIM rules do.
Note that every other comparison is case-sensitive too, unlike many 4.x
`<match>` patterns.

## Limits

- Same scope as 4.x: the access-log layer sees request lines only (no POST
  bodies), and the exec layer uses the service account as the proxy for "came
  from the web app", so run Node.js under its own account.
- First-seen needs history: on a new host every binary is new for its first run.
- FIM rules see creates and modifies as the agent reports them; the agent's own
  `<ignore>` (e.g. `node_modules`) wins before any rule runs.
