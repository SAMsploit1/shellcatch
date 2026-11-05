# Draft upstream issues — wazuh/wazuh-indexer-security-analytics (5.0.0-rc2)

Drafts only. Not filed. Found while migrating a community ruleset to 5.0 (see
`detections/web-to-shell/wazuh5`). Each was reproduced on a live detector
with a probe rule plus a control rule, and the compiled query was read from
`.opensearch-sap-custom-rules-config`.

Environment for all three: Wazuh 5.0.0-rc2 all-in-one from
`wazuh-install-5.0.0-rc2.sh -a -d pre-release`, Ubuntu 24.04, agent 5.0.0-rc2.
Code references are to tag `v5.0.0-rc2`.

---

## Issue 1 — `|re` values containing `/` never match

**Summary.** A Sigma `|re` value that contains a forward slash compiles to a
Lucene query-string regex whose `/` delimiter is closed early, so the rule
never matches. This affects most regexes over Linux paths
(`process.executable`, `file.path`, `url.path`).

**Reproduce.**

```yaml
detection:
  condition: k and x
  k: {rule.name: web_exec_php, event.action: started}
  x: {process.executable|re: "/usr/bin/id$"}
```

Event: an auditd execve of `/usr/bin/id` (normalized by the standard `auditd`
integration). Control: the same rule with `process.executable|re: "bin.id$"`.

**Expected.** Both rules produce a finding.
**Actual.** The control produces a finding; the slash version never does,
on the live detector and in `POST /_plugins/_content_manager/logtest/detection`.

Compiled queries:

```
process.executable: /.*(/usr/bin/id)/    # slash version
process.executable: /.*(bin.id)/         # control
```

**Cause.** `OSQueryBackend` sets `reEscape = Arrays.asList("\"")` and
`reExpression = "%s: /%s/"`. `/` is not escaped, so it terminates the regex
term. Escaping it in the rule (`\/`) doesn't work either, because the
backslash is itself escaped.

**Suggested fix.** Add `/` to `reEscape`
(`Arrays.asList("\"", "/")`), so `escape()` emits `\/`, which Lucene accepts
inside `/…/`. `toLuceneRegex` reads anchors from the raw pattern, so they are
unaffected. A unit test in `QueryBackendTests` with `|re: "/usr/bin/id$"`
asserting `process.executable: /.*(\/usr\/bin\/id)/`-style output would cover
it.

**Impact.** None of the 368 standard rules in rc2 put a `/` in a regex, so the
standard content is unaffected; custom Linux rules hit it quickly, and the
failure is silent (the rule is accepted).

---

## Issue 2 — a `not` nested inside a negated group compiles to `NOT NOT`, matching nothing

**Summary.** For `not (A and not B)`, the backend pushes the outer negation
down with De Morgan's law but emits `NOT NOT B` for the inner negation instead
of cancelling it. Lucene's query-string parser doesn't treat `NOT NOT B` as
`B`, so the whole clause never matches.

**Reproduce.**

```yaml
detection:
  condition: k and sh and not (s and not m)
  k:  {rule.name: web_exec_php, event.action: started}
  sh: {process.name: sh}
  s:  {process.command_line|startswith: "sh -c -- /usr/sbin/sendmail -t -i -f"}
  m:  {process.command_line|contains: ";"}
```

Control: `condition: k and sh and (not s or m)` (logically identical).

Events: `sh -c -- ping -c 1 -W 1 127.0.0.1;id` (s false) and
`sh -c -- /usr/sbin/sendmail -t -i -fx@example.com\;id` (s and m true).

**Expected.** Both rules match both events.
**Actual.** The control matches both (3 findings: the second command also
logs a failed execve); the nested version matches nothing, live and in
logtest.

Compiled queries (trimmed):

```
not (s and not m)  ->  ((NOT s) OR ((NOT NOT process.command_line: *;*)))
(not s or m)       ->  ((NOT s)) OR (process.command_line: *;*)
```

**Cause.** `convertConditionNot` calls `convertCondition(argType, true,
applyDeMorgans)` and prefixes `notToken` regardless of `applyDeMorgans`. When
the call comes from a negated group (`applyDeMorgans == true`), the field
conversion already emits `NOT field: value`, so the prefix doubles it.

**Suggested fix.** In `convertConditionNot`, when `applyDeMorgans` is true the
two negations cancel: return the argument converted positively
(`convertCondition(argType, false, false)` for an item,
`convertConditionGroup(argType, false, false)` for a group) and don't add
`notToken`. Unit test: `not (a and not b)` should compile to
`(NOT a) OR (b)` (modulo grouping).

**Impact.** Silent: the rule is accepted and simply never fires. Allowlist
patterns ("X unless Y, unless Z") produce exactly this shape.

---

## Issue 3 — `|re|i`, `|re|m`, `|re|s` are documented but rejected

**Summary.** The regex flag submodifiers are documented in
`wazuh/wazuh: docs/guide/migration/rules-4x-to-5x.md` (Detection modifiers
table) and in `wazuh-indexer-plugins: docs/ref/modules/ruleset-management/rules.md`
(`re` → submodifiers `i`, `m`, `s`), but rc2 rejects any rule that uses them:

```
POST /_plugins/_content_manager/rules  ...  "url.query|re|i": "(^|&)cmd="
-> 400 {"SigmaDetectionError":"Sigma rule must have a detection definitions: Unknown modifier i"}
```

`SigmaModifierFacade` registers `contains, startswith, endswith, base64,
base64offset, wide, windash, re, cidr, all, lt, lte, gt, gte, exists` and no
flag modifiers.

**Suggested fix.** Either implement them (Lucene's regexp query has a
`case_insensitive` flag; the query-string `/…/` syntax doesn't, so this may
need the backend to emit a regexp query instead), or remove them from both
documents and note that matching is case-sensitive.
