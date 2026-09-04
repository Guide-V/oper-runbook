# spec.md: decision log

Running record of what was built and why. Newest entries at the bottom of each section.

## 2026-09-04: repository bootstrap and `regex-finder`

### Goal

Consolidate the operations team's scripts in one repo. First script: locate `$regex` usage in the slow
queries that Performance Advisor reports, for both Atlas and Enterprise Advanced deployments, and
say which regexes are index-hostile.

### Decisions

1. **One Python package, one CLI (`mongoops`), sub-command per script.**
   Ops scripts accumulate shared plumbing (API auth, log parsing, output formatting). A package
   with `common/` keeps that DRY and gives every script the same UX (`--format`, `--output`,
   `.env` loading). Python 3.12 was already on the workstation; `uv` was not, so the project is
   plain PEP 621 + `venv`/`pip` and works with `uv` unchanged.

2. **Performance Advisor is the primary source for both products, via one shared fetch.**
   Atlas (`/api/atlas/v2/groups/{g}/processes/{p}/performanceAdvisor/slowQueryLogs`) and
   Ops Manager (`/api/public/v1.0/groups/{g}/hosts/{h}/performanceAdvisor/slowQueryLogs`) return
   the same `{slowQueries: [{line, namespace}]}` payload where `line` is a raw mongod log line.
   Only the URL prefix, auth and the list endpoint (processes vs hosts) differ, so
   `common/perf_advisor.py` holds the request/pagination code once and the two API modules are
   thin. Verified against the current Atlas Admin API v2 spec and the Ops Manager API docs.

3. **Two extra sources so EA without Ops Manager is covered and testing needs no Atlas account.**
   `logfile` parses `mongod.log` directly (also `.gz` and stdin); `live` reads the server's
   `getLog: "global"` ring buffer over a connection. Both feed the same parser, so the detector is
   exercised against real server output in tests without any API credentials.

4. **Log-line parser supports JSON (4.4+) fully and legacy 4.2 text best-effort.**
   Everything the customer runs today should be 4.4+, but EA estates can lag. The legacy path extracts
   `planSummary`, counters and the command body, and uses a regex-literal scanner (with
   enclosing-field resolution for `$in` / `$not`) because the 4.2 body is not JSON. Documented as
   best effort.

5. **Detector is a pure structural walk over the command document.**
   Real 8.0 logs (captured from atlas-local) show three encodings of a regex: `$regex` operator
   with `$options`, BSON literal as `{"$regularExpression": {pattern, options}}`, and the
   aggregation expressions `$regexMatch` / `$regexFind` / `$regexFindAll` (`regex` may be a string
   or a literal, `options` a sibling). The walk tracks the owning field through `$in`, `$not`,
   `$or`, `$elemMatch`, `$match`, `$expr`; for expression operators the field is taken from
   `input` (`"$name"` -> `name`). getMore lines are analysed via `originatingCommand` but skipped
   by default because they are continuations, not new queries.

6. **Classification follows the MongoDB `$regex` index rules, worst first.**
   `case_insensitive` > `leading_wildcard` > `negated` > `unanchored` > `anchored` > `prefix`.
   Case-insensitivity dominates because even `^prefix` with `i` cannot use a regular index.
   `negated` was added after the atlas-local run showed `{name: {$not: /^Anan/}}` planning as
   COLLSCAN despite a prefix pattern. Expression operators (`$regexMatch` inside `$expr`) ignore
   the negation flag since they never get index bounds anyway.

7. **Batched writes are re-namespaced from `db.$cmd` to `db.<collection>`.**
   mongod logs the batch `update`/`delete` command against `db.$cmd`; the collection is the value
   of the first command key. Both the batch line and the per-write line are reported (counts
   match the log; the `command` column distinguishes them) rather than guessing which to drop.

8. **Atlas cluster -> processes via the cluster's connection string (revised same day).**
   First version matched `userAlias` on a `<cluster>-` prefix. On a real project the aliases
   were `ac-qwe456-shard-00-00.<hash>.mongodb.net` and hostnames `atlas-abc123-shard-...`,
   neither derived from the cluster name, so nothing matched. The reliable link is
   `GET /groups/{g}/clusters/{name}` -> `connectionStrings.standard`, whose hosts equal the
   processes' `userAlias`. `select_processes` now takes that host set and matches on alias or
   hostname (mongos on sharded clusters share hostnames with the shard mongods). Explicit
   `--process host:port` remains available.

9. **Auth mirrors the official CLIs.** Same environment variable names as the Atlas CLI
   (`MONGODB_ATLAS_PUBLIC_API_KEY`, ...) and mongocli (`MONGODB_OPS_MANAGER_URL`, ...). Atlas
   supports digest API keys and service accounts (OAuth2 client credentials with token refresh);
   Ops Manager supports digest plus `--ca-file` / `--insecure` for self-signed TLS. `.env` is
   git-ignored, `.env.example` is committed.

10. **`live` connection settings.** One-shot, single-threaded command, so `maxPoolSize=1`,
    5 s server-selection and connect timeouts, 30 s socket timeout, `appname` set for
    traceability in server logs, client closed via context manager. (Per the mongodb-connection
    skill: values justified by the workload rather than copied defaults.)

11. **Functional style.** Frozen `slots` dataclasses everywhere (`SlowQuery`, `RegexUsage`,
    `Finding`, `SummaryRow`, `SlowQueryWindow`), tuples instead of lists in return values, pure
    parse/detect/summarise/render functions; I/O confined to `sources.py`, the API modules and
    `cli.py`.

12. **Testing strategy.**
    * Unit (default `pytest`): detector, parser, analysis, report, API clients
      (`httpx.MockTransport`), CLI (`CliRunner`). Fixtures include 22 real slow-query lines
      captured from atlas-local 8.0 (`tests/fixtures/atlas_local_slow_queries.jsonl`) and a
      hand-written legacy 4.2 log.
    * Integration (`-m integration`, needs `MONGOOPS_TEST_MONGODB_URI`): seeds a database on
      atlas-local, forces `slowms=-1`, runs regex queries, verifies the `live` source and CLI.
    * Golden path covered: log line -> finding -> summary -> csv/json/table, plus the Atlas and
      Ops Manager request/response cycle end to end with mocked HTTP.
    * Live Atlas verification (same day, see 14).

13. **atlas-local was sufficient for testing; no real Atlas cluster was needed.**
    `atlas deployments setup mongoops-regex-test --type local --mdbVersion 8.0 --port 27099` gives
    a real mongod whose `getLog` output is byte-for-byte the same format Performance Advisor
    returns in `line`. Docker (OrbStack) is required; the deployment is left running after the
    task and can be removed with `make atlas-local-down`.

14. **Live Atlas verification and what it taught.** Run against project `67da6e57...`,
    cluster `cluster-free` (an M20 despite the name) with a programmatic API key.
    * Role: the API spec lists *Project Data Access Read Only* as sufficient and that matched
      reality; a key with only `GROUP_READ_ONLY` could list clusters and processes but got
      `401 USER_UNAUTHORIZED` on `slowQueryLogs`. Chosen key roles:
      `GROUP_READ_ONLY,GROUP_DATA_ACCESS_READ_ONLY`. Debugging detour worth recording: I
      spent several role changes on a *different* key than the one in `.env` (two keys had
      been created); the fix was to check `MONGODB_ATLAS_PUBLIC_API_KEY` against
      `atlas organizations apiKeys list` first. The README troubleshooting table exists so the
      next person does that in one step.
    * Org setting `apiAccessListRequired: true` means keys need an IP entry; only an org user
      administrator (or the key itself) may add one, a Project Owner cannot.
    * Cluster -> process mapping fixed as described in 8.
    * Seeding: Atlas will not let us force `slowms`, and the Atlas-managed threshold is based
      on the cluster's average op time, so `scripts/dev/seed_regex_workload_atlas.js` inserts
      300k documents and repeats each regex shape three times to make sure the scans exceed it.
      A temporary DB user scoped to the cluster with `readWrite@mongoops_test` was created for the
      seed and deleted afterwards. Lesson: `readWrite` cannot `dropDatabase` (needs `dbAdmin`),
      so the `mongoops_test.customers` collection (~40 MB) was left on `cluster-free`; the seed
      script drops and recreates it, and an `atlasAdmin` user can drop the database in one call.
    * Result: 18 slow-query lines on the primary, 21 regex usages in 6 shapes, categories
      matched expectations; anchored-prefix and `$match` controls stayed under the slow
      threshold and correctly did not appear.

15. **`make test-atlas-local` / `make test-atlas-live` as the two golden-path checks.**
    The live check is a bash script (`scripts/dev/atlas_live_check.sh`) rather than a pytest
    fixture because it needs the Atlas CLI's logged-in session to create a DB user, and because
    the Performance Advisor ingestion wait (minutes) does not belong inside a test. The script
    creates a uniquely named, cluster-scoped temporary user, uses the seed start time as
    `--since` so stale data from previous runs cannot make the check pass, polls until at least
    four regex shapes are reported, then hands verification to `pytest -m atlas_live`, and
    cleans up in an `EXIT` trap. Dropping the collection (not the database) keeps the temporary
    user at `readWrite`. `atlas_live` joins `integration` in pytest's default deselection so
    `make test` stays offline.
    First run failed with "Authentication failed" and taught two things now baked in: (a) the
    script must not `export` the whole `.env`, because the Atlas CLI honours
    `MONGODB_ATLAS_*_API_KEY` and silently switches from the logged-in profile to the read-only
    key, so `dbusers create` fails; only `MONGODB_ATLAS_PROJECT_ID` is read, mongoops loads `.env`
    on its own. (b) Never wrap CLI calls in `|| true`; the wrapper keeps the exit status and only
    filters the update nag. Measured: ingestion lag on the M20 was ~2 minutes.

16. **`make probe-atlas` / `make probe-local` for instant, read-only checks.** Thin wrappers over
    the CLI with `ATLAS_CLUSTER`, `SINCE`, `NAMESPACE`, `VIEW` and a catch-all `ARGS`, so the
    common "what does Performance Advisor say right now" question is one short command without
    remembering flags. While adding `probe-local` we measured the `getLog` buffer on atlas-local:
    1024 lines lasted ~8 minutes because mongot and health checks log ~2 connection lines per
    second. That is a property of the `live` source, not a bug, and is now documented next to the
    target; the `logfile` source is the answer for anything older.

17. **HTML dashboard: one self-contained file, written next to every probe/test.**
    * Why a fourth format rather than a web app: the audience is an ops team attaching evidence
      to tickets and EA jump hosts with no internet. A single HTML file with inline CSS and
      ~40 lines of vanilla JS (text filter, column sort) needs nothing installed and survives
      email. No chart library; the category bars are plain CSS widths.
    * `--html FILE` is an *additional* output on every command, so the terminal table stays
      the primary interface and the dashboard is a side effect; `--format html` exists for
      piping. `--html` always renders both views regardless of `--view`, since the file is for
      reading later.
    * `ReportMeta` carries source/target/window/filters into the header so a dashboard is
      self-describing when it is found a week later. Connection strings are credential-stripped
      before they reach it (`_redact_uri`).
    * The summary logic moved to `summary.py` so `report.py` and `html_report.py` can both
      import it without a cycle; `report.render` stays the single pure entry point and
      re-exports `summarize`/`SummaryRow` for existing callers.
    * All log-derived text goes through `html.escape` (covered by a test with a `<script>`
      appName). Rich wraps long `file://` URIs at 80 columns, which breaks click-to-open, so the
      dashboard path is printed with `soft_wrap=True`.
    * Make writes `reports/<target>-<UTC stamp>.html` plus a `<target>-latest.html` symlink;
      `reports/` is git-ignored. Verified visually with headless Chrome on both the fixture and
      the live `cluster-free` data.

18. **Remedies: recommend MongoDB Search, but only where it is the right fix.**
    Question raised: "should the tool recommend Atlas Search instead?" Answer: as a targeted
    per-shape remedy, not a blanket one, because (a) several shapes have a cheaper fix with no
    new infrastructure (collation index for case-insensitive prefix, reversed field for suffix
    on identifiers), (b) `$search` is aggregation-only so regexes in `update`/`delete`/
    `findAndModify` filters cannot move to it, (c) Search is eventually consistent so it is
    wrong for validation/uniqueness checks, (d) it costs money and, on EA, a deployment project
    (GA as a paid add-on since 2026-06-30, MongoDB 8.2+, `mongot` via the Kubernetes operator).
    Implementation (`remedy.py`, pure, unit-tested as a rule table):
    * inputs are only what the slow-query line already has: category, command, pattern,
      options, plan summary, keys/docs examined, nreturned, operator and path;
    * order of rules: expression operators (`$regexMatch`/`$regexFind` outside `$expr` have no
      index implication -> `none`; prefix inside `$expr` -> `rewrite` to a plain predicate),
      negated -> `rewrite`, prefix -> `none` or `btree_index` on COLLSCAN, case-insensitive
      literal prefix -> `collation_index`, identifier suffix -> `reversed_field`, write path ->
      `fix_filter`, heavy scan -> `search`, otherwise `monitor`;
    * "heavy" = >= 1000 keys/docs examined, or COLLSCAN with scanned/returned >= 100. This is
      what stops a 3-document atlas-local collection from being told to buy Search Nodes; the
      fixture test asserts `search` never appears there while the live M20 data yields it for
      the two free-text scans over 300k keys;
    * "identifier" = literal of >= 3 chars from `[0-9A-Za-z_+-]`, at least half digits
      (MSISDN, account and order numbers). Anything with spaces or dots is treated as text;
    * the instruction text substitutes the real field name (`with_field`) so it can be pasted;
    * `Finding` and `SummaryRow` gained `remedy`/`remedy_how`, so CSV/JSON/table/HTML all carry
      it without renderer-specific logic. The summary row uses the most frequent remedy in the
      group, ties going to the more involved one since it had the evidence;
    * the dashboard gets three KPI cards (Search / index fix / query rewrite), a "What to do"
      section grouped by remedy, remedy badges with the instruction as tooltip, and the Search
      deployment note whenever Search is recommended.

### Known limitations / follow-ups

* `live` only sees the last ~1024 log lines of one node; use `logfile` or the API sources for
  history.
* Truncated log lines (huge commands) may hide the regex; they are flagged, not reconstructed.
* Legacy 4.2 parsing can be confused by string values containing braces.
* Possible next sources: `system.profile` (database profiler) for EA nodes where neither Ops
  Manager nor log files are reachable.
* Atlas `includeMetrics` / `includeOpType` response fields are not used yet; the same numbers
  are parsed from the log line, which also works for Ops Manager.
* `--fail-on <remedy,...>` (non-zero exit when a listed remedy appears) would let CI gate without
  the `jq` step documented in the README. Deferred until the customer settles on a policy; the
  README's block/warn/ignore split is the proposed default.

19. **README quick start and automation guidelines, no integration code.** The customer wanted
    to try the tool and asked how it would fit Ansible / CI. Chosen to document rather than ship
    playbooks or workflow files: their tooling is unknown, and the tool's properties (read-only,
    JSON output, exit 0/2, env-var credentials, single-file HTML) make any integration a few
    lines they own. The gate is expressed with `jq` on `-f json` output, validated against the
    fixture: block on `search`/`fix_filter`/`btree_index`, warn on the index/rewrite remedies,
    and a baseline "ratchet" for clusters that already have findings. The guidance places the
    gate after a workload ran (post-deploy/nightly, or inside integration tests with
    `slowms: -1` and the `live` source), because Performance Advisor cannot see queries that
    never executed. Repository published at https://github.com/Guide-V/oper-runbook.

20. **Customer-neutral naming everywhere, including identifiers.** The repo is public, so the
    customer must not appear in prose or in identifiers. Package/CLI `mongoops`, env prefix
    `MONGOOPS_*`, test db `mongoops_test`, local deployment `mongoops-regex-test`, project
    `oper-runbook`; seed and fixture data use `example.co.th` / `*.example.local`. The captured
    slow-query fixture was normalised with the same substitution, which is safe because the
    tests assert on the same namespace. History was squashed to a single commit so that no
    earlier revision carries customer-specific names.
