# oper-runbook

Operational scripts for the MongoDB operations team, covering both **Atlas** and
**Enterprise Advanced (EA)** deployments. Everything ships as one Python package with a single
entry point, `mongoops`, and one sub-command per script.

| Script | Command | What it does |
| --- | --- | --- |
| regex-finder | `mongoops regex-finder ...` | Finds `$regex` usage in slow queries reported by Performance Advisor (Atlas or Ops Manager) or found in mongod logs, and classifies each regex for index-friendliness. |
| waf-check | `mongoops waf-check ...` | Scores one Atlas cluster against the [operational-readiness checklist](https://www.mongodb.com/docs/atlas/architecture/current/operational-readiness-checklist/) and the five Well-Architected pillars, using read-only Admin API facts and a landing-zone policy you own. Atlas only. |

## Requirements

* Python 3.12+
* For Atlas: a programmatic API key **or** a Service Account with **Project Data Access Read
  Only** (or Project Observability Viewer). Plain Project Read Only can list clusters and
  processes but gets `401 USER_UNAUTHORIZED` on the Performance Advisor endpoint (verified).
  `waf-check` works with Project Read Only and reports the few checks that need Project Owner
  as `UNKNOWN` (see its section).
* For EA: Ops Manager / Cloud Manager API key, or read access to the `mongod.log` files.
* Optional for local testing: [Atlas CLI](https://www.mongodb.com/docs/atlas/cli/) + Docker
  (for `atlas deployments setup --type local`) and `mongosh`.

## Install

```bash
make install            # python3 -m venv .venv && pip install -e ".[dev]"
cp .env.example .env    # fill in API keys; .env is git-ignored
.venv/bin/mongoops --help
```

`uv` users: `uv venv && uv pip install -e ".[dev]"` works the same, the project is standard PEP 621.

## Quick start: your first run in 15 minutes

Nothing in this tool writes to a cluster. It reads Performance Advisor (or a log file) and
produces a report, so it is safe to point at production.

### Step 1: install

```bash
git clone https://github.com/Guide-V/oper-runbook.git && cd oper-runbook
python3 --version          # needs 3.12+
make install               # creates .venv and installs mongoops into it
.venv/bin/mongoops --version
```

No `make`? The equivalent is `python3 -m venv .venv && .venv/bin/pip install -e .`.

### Step 2: pick the path that matches your deployment

**A. Atlas (Performance Advisor via the Admin API)**

1. Create a read-only API key with the Atlas CLI (or in the UI under *Project > Access Manager >
   API Keys*). The important part is the role: `GROUP_DATA_ACCESS_READ_ONLY` ("Project Data
   Access Read Only"). Plain Project Read Only is not enough for Performance Advisor.

   ```bash
   atlas projects apiKeys create --projectId <PROJECT_ID> --desc "mongoops regex-finder" \
     --role GROUP_DATA_ACCESS_READ_ONLY,GROUP_READ_ONLY
   ```

2. If your organisation enforces *Require IP Access List for the Administration API*, add the IP
   of the machine that will run the tool to the key's access list (an org user administrator has
   to do this).
3. Put the key and project id in `.env`:

   ```bash
   cp .env.example .env
   # MONGODB_ATLAS_PUBLIC_API_KEY=...   MONGODB_ATLAS_PRIVATE_API_KEY=...   MONGODB_ATLAS_PROJECT_ID=...
   ```

4. Run against one cluster, last 24 hours, summary only:

   ```bash
   .venv/bin/mongoops regex-finder atlas --cluster <ClusterName> --since 24h --view summary
   ```

   You should see `N process(es) selected` followed by one line per node with the number of slow
   query lines fetched. If that works, the credentials are right; anything else is in the
   troubleshooting table under [Credentials and environment](#credentials-and-environment).

**B. Enterprise Advanced with Ops Manager / Cloud Manager**

1. Create an API key on the Ops Manager project (start with Project Read Only; if Performance
   Advisor answers `401`, raise it to Project Data Access Read Only as with Atlas).
2. Fill the `MONGODB_OPS_MANAGER_*` variables in `.env` (`URL`, keys, `PROJECT_ID`, and
   `CA_FILE` if Ops Manager uses an internal certificate).
3. Run against one replica set:

   ```bash
   .venv/bin/mongoops regex-finder ops-manager --replica-set <rsName> --since 24h --view summary
   ```

**C. Enterprise Advanced without Ops Manager, or you just have log files**

No credentials needed at all. Copy a `mongod.log` (or `.gz`) from a node and run:

```bash
.venv/bin/mongoops regex-finder logfile /path/to/mongod.log.gz --min-ms 100 --view summary
```

The same works for Atlas logs downloaded with
`atlas logs download <hostname> mongodb.gz --projectId <PROJECT_ID>` when you prefer not to hand
out an API key.

### Step 3: read the summary

The summary table has one row per *shape* (`namespace`, `field`, `command`, `category`), worst
first. Two columns matter most:

* `category` says how badly the regex defeats indexes (see [Reading the output](#reading-the-output)).
  `prefix` is fine; everything else scans.
* `remedy` says what to do about it (see [Remedies](#remedies-what-to-do-about-each-shape)).
  The full instruction, with the real field name, is in the `remedy_how` column of the CSV/JSON
  and in the "What to do" section of the dashboard.

Sanity checks on the numbers: `collscan` > 0 and `docs examined` far above what the query
returned confirm the regex is really the cost, not just present.

### Step 4: produce something you can share

```bash
.venv/bin/mongoops regex-finder atlas -c <ClusterName> --since 7d \
  --html reports/<ClusterName>.html -f csv -o reports/<ClusterName>.csv
open reports/<ClusterName>.html
```

The HTML is a single file with no external dependencies: attach it to a ticket or mail it. The
CSV has one row per finding for spreadsheets. Add `-n db.coll` to focus on one collection.

### Step 5 (optional): try it without touching a real cluster

With the Atlas CLI and Docker installed, `make test-atlas-local` spins up a local MongoDB, seeds a
regex workload and shows the resulting report in about ten seconds. It is a good way to see what
every category and remedy looks like before reading production output.

### If you see nothing

`0 slow query line(s)` on every node means no operation crossed the slow threshold in the window.
Widen it (`--since 7d`), or check the cluster tier: Performance Advisor needs M10 or larger.
`0 regex usage(s) found` with slow lines present is a genuine result: the slow queries are slow
for other reasons.

## regex-finder

### Why

MongoDB can only turn a `$regex` into an index *range* scan when the pattern is a
**case-sensitive prefix** (`^literal...`). Every other shape (unanchored, leading `.*`,
`$options: "i"`, or under `$not`/`$nin`) has to test every index key or every document, which is
where a lot of slow-query pain on customer clusters comes from. Performance Advisor already
collects the slow queries; this tool extracts the regexes from them and tells you which ones are
the problem.

### Sources

| Sub-command | Deployment | Where the slow queries come from |
| --- | --- | --- |
| `atlas` | Atlas | Atlas Admin API `GET /groups/{g}/processes/{p}/performanceAdvisor/slowQueryLogs`, for every process of a cluster (resolved via the cluster's connection-string hosts) |
| `ops-manager` | EA with Ops Manager / Cloud Manager | `GET /groups/{g}/hosts/{h}/performanceAdvisor/slowQueryLogs`, for every selected host |
| `logfile` | EA without Ops Manager, or exported Atlas logs | A `mongod.log` (JSON 4.4+ or legacy 4.2 text), `.gz` supported, `-` for stdin |
| `live` | Any (great for atlas-local) | `db.adminCommand({getLog: "global"})`, the server's in-memory ring buffer (last ~1024 lines) |

All four feed the same parser and detector, so the output is identical regardless of source.

### Examples

```bash
# Atlas: whole cluster, last 24h (API default), table with summary + details
mongoops regex-finder atlas --project-id 5f1a... --cluster Cluster0

# Atlas: last 6 hours, one namespace, CSV for a ticket
mongoops regex-finder atlas -p 5f1a... -c Cluster0 --since 6h -n shop.orders -f csv -o out/regex.csv

# Ops Manager (EA): one replica set, JSON summary only
mongoops regex-finder ops-manager -p 5f1a... --replica-set rs0 -f json --view summary

# Ops Manager with a self-signed certificate
mongoops regex-finder ops-manager -p 5f1a... --ca-file /etc/ssl/om-ca.pem

# Log file from an EA node (gz ok), only ops slower than 100 ms
mongoops regex-finder logfile /var/log/mongodb/mongod.log.gz --min-ms 100

# Live node
mongoops regex-finder live --uri "mongodb://user:pw@db1:27017/?directConnection=true"

# Any source: keep the terminal table and also write an HTML dashboard for sharing
mongoops regex-finder atlas -p 5f1a... -c Cluster0 --html reports/cluster0.html
```

Common options: `--format table|csv|json|html`, `--view summary|details|both`, `--output FILE`,
`--html FILE`, `--namespace db.coll` (repeatable), `--min-ms N`, `--include-getmore`,
`--max-rows N` (table only). API sources add `--since` (`24h`, `7d`, or ISO-8601), `--duration`,
`--n-logs`.

### HTML dashboard

`--html FILE` writes a single self-contained HTML page (inline CSS and a few lines of vanilla JS,
no CDN, opens offline or from a ticket attachment) in addition to the normal stdout output;
`--format html` sends the same page to stdout / `--output` instead. The page shows:

* header chips: source, target (cluster / hosts / file / credential-stripped URI), time window,
  filters, generation time;
* at-a-glance cards: regex usages, distinct shapes, index-defeating shapes, COLLSCAN operations,
  slowest op, namespaces affected, and how many shapes need Search / an index fix / a rewrite;
* "What to do": one card per remedy listing the shapes it applies to with the concrete
  instruction, plus the Search deployment note when Search is recommended;
* a by-category bar chart, the shapes table (worst first, same columns as the terminal summary),
  and the full findings table with a live text filter and click-to-sort headers;
* the category and remedy legends.

Every `make probe-*` and `make test-atlas-*` run writes one to `reports/<target>-<UTC stamp>.html`
and refreshes `reports/<target>-latest.html` (`reports/` is git-ignored):

```bash
make probe-atlas && open reports/probe-atlas-latest.html
```

### Reading the output

Each finding is one regex inside one slow operation, with the field it targets, the pattern and
options, the plan summary, timings and scan counters from the log line. The summary groups
findings by `(namespace, field, command, category)` and sorts the worst categories first:

| Category | Meaning | Index impact |
| --- | --- | --- |
| `case_insensitive` | `$options: "i"` or `(?i)` | Cannot use a regular index efficiently. Consider a case-insensitive collation index or a normalised (lower-cased) field. |
| `leading_wildcard` | starts with `.*` or `^.*` | Anchor is useless, scans everything. |
| `negated` | under `$not` / `$nin` | No index bounds can be derived. |
| `unanchored` | no leading `^` | Every index key (or document) is tested. |
| `anchored` | `^` followed by a meta character, e.g. `^(a\|b)`, `^\d` | Full index scan, no range. |
| `prefix` | `^literal`, case-sensitive | Index range scan possible. This is the shape you want. |

### Remedies: what to do about each shape

Every finding also carries a `remedy` and a one-sentence `remedy_how` with the real field name
filled in (the dashboard groups them under "What to do"). The rules are deliberately
conservative: the cheapest fix that works wins, MongoDB Search is only suggested when the
operation is on the read path *and* the log shows a real scan, and write-path regexes are never
sent to Search because `$search` is an aggregation-only stage.

| Remedy | When | What it tells you to do |
| --- | --- | --- |
| `none` | case-sensitive prefix using an index; or `$regexMatch`/`$regexFind` used as a projection, not a filter | nothing |
| `btree_index` | prefix regex but the plan is `COLLSCAN` | create a normal index on the field |
| `collation_index` | case-insensitive regex whose body is a literal prefix (`^som` with `i`) | `{ collation: { locale, strength: 2 } }` index and query with the same collation using a case-sensitive prefix |
| `reversed_field` | suffix match on an identifier-like literal (`^.*99999$` on an MSISDN, digit-heavy, no spaces) | store a reversed copy, index it, query `{ field_rev: /^99999/ }` |
| `rewrite` | negated regex (`$not`/`$nin`); or a prefix regex inside `$expr` | invert the predicate / add a flag field; move the regex to a plain predicate |
| `fix_filter` | any remaining regex in an `update`, `delete`, `remove`, `findAndModify` filter | `$search` cannot run there: narrow the filter on an indexed field, or `$search` for `_id`s then mutate by `_id` |
| `search` | unanchored / leading-wildcard / case-insensitive regex on free text, on `find`/`aggregate`, with a heavy scan (>= 1000 keys or docs examined, or `COLLSCAN` returning < 1% of what it scanned) | create a MongoDB Search index on the field and query with `$search` first; the sentence names the operator (`text`/`phrase` with the standard analyzer, `wildcard`/`regex` over a keyword analyzer, or `autocomplete` for type-ahead) |
| `monitor` | same shapes without the scan evidence (small collection) | no action yet; recheck as the collection grows |

Search availability differs by deployment and the dashboard says so next to the Search card:
Atlas M10+ (optionally dedicated Search Nodes), or self-managed as the paid Enterprise Advanced
add-on on MongoDB 8.2+ with `mongot` deployed through the Kubernetes operator. Search is
eventually consistent, so validation and uniqueness checks stay on B-tree indexes.

Notes:

* Writes appear twice in mongod logs (once per individual write with a plan summary, once for
  the batched `update`/`delete` command). Both are reported so counts match the log; use the
  `command` column to tell them apart.
* `getMore` continuations are skipped by default (they are the same query); `--include-getmore`
  counts them.
* Truncated log lines (very large commands) are flagged in the `truncated` column; the regex may
  not be visible in them.
* Legacy 4.2 text logs are parsed best-effort: the command body is not JSON, so the detector
  uses a regex-literal scanner rather than a structural walk.

### Credentials and environment

Variable names follow the Atlas CLI and mongocli so existing shell profiles work. See
`.env.example`. `mongoops` loads `.env` from the current directory (override with `--env-file`).

Creating a suitable Atlas key with the Atlas CLI:

```bash
atlas projects apiKeys create --projectId <PROJECT_ID> --desc "mongoops" \
  --role GROUP_DATA_ACCESS_READ_ONLY,GROUP_READ_ONLY
# If the org enforces "Require IP Access List for the Administration API", add your IP.
# Only an org user administrator (or the key itself, once it has an entry) may do this:
atlas organizations apiKeys accessLists create --apiKey <API_KEY_ID> --orgId <ORG_ID> --currentIp
```

Troubleshooting `atlas`:

| Symptom | Cause |
| --- | --- |
| `no processes matched cluster=...` | Cluster name typo (the cluster resource lookup is case-sensitive). List with `atlas clusters list`. |
| `401 USER_UNAUTHORIZED` on `.../performanceAdvisor/slowQueryLogs` while processes listed fine | Key lacks a Data Access role (see above). |
| `403 IP_ADDRESS_NOT_ON_ACCESS_LIST` | Key has an access list that does not include this machine. |
| processes selected, `0 slow query line(s)` everywhere | Nothing exceeded the Atlas slow threshold in the window, or the cluster is below M10 (no Performance Advisor). |

| Variable | Used by |
| --- | --- |
| `MONGODB_ATLAS_PUBLIC_API_KEY`, `MONGODB_ATLAS_PRIVATE_API_KEY` | `atlas` (HTTP digest) |
| `MONGODB_ATLAS_CLIENT_ID`, `MONGODB_ATLAS_CLIENT_SECRET` | `atlas` (service account, used when no API key is set) |
| `MONGODB_ATLAS_PROJECT_ID` | default for `atlas --project-id` |
| `MONGODB_OPS_MANAGER_URL`, `MONGODB_OPS_MANAGER_PUBLIC_API_KEY`, `MONGODB_OPS_MANAGER_PRIVATE_API_KEY`, `MONGODB_OPS_MANAGER_PROJECT_ID`, `MONGODB_OPS_MANAGER_CA_FILE` | `ops-manager` |
| `MONGODB_URI` | default for `live --uri` |

## waf-check

### Why

The Well-Architected enablement session ended with three decisions: use MongoDB's
operational-readiness checklist as the baseline, derive an organisation-specific checklist from
the landing zone, and treat Performance Advisor as a CI/CD quality gate. `waf-check` turns the
first two into a repeatable, read-only report: it reads the cluster and project configuration
through the Atlas Admin API, compares it with a policy file, and produces a pillar scorecard with
the evidence and the Atlas fix for every gap. Items the API cannot see (DR drills, training,
CSFLE design, org structure) are listed under "Discuss these" instead of being faked as green.

### Quick start

```bash
# 1. Score a cluster with MongoDB's defaults (needs MONGODB_ATLAS_* in .env, see below)
mongoops waf-check atlas -c <ClusterName> --html reports/waf.html
open reports/waf.html

# 2. Write a landing-zone policy, answer a few questions, then score against it
mongoops waf-check init -i -o landing-zone.prod.yaml
mongoops waf-check atlas -c <ClusterName> --policy landing-zone.prod.yaml -f json -o reports/waf.json

# 3. See every check id and its default severity (the keys of the policy's `checks:` section)
mongoops waf-check checks
```

`make probe-waf ATLAS_CLUSTER=<name> [POLICY=file]` does step 1 and drops the HTML in `reports/`.

### How a check is scored

Three layers, so the official checklist and the customer's landing zone stay separate:

| Layer | Lives in | Role |
| --- | --- | --- |
| Catalog | `waf_check/catalog.py` | Stable check ids mapped to the checklist, pillar, default severity, docs link. |
| Facts | `waf_check/facts.py` | Raw Admin API documents for the cluster and its project, fetched one by one. |
| Policy | `landing-zone.yaml` (from `waf-check init`) | What "good" means here: network mode, RPO window, required tags and alerts, and the severity (`fail` / `warn` / `off`) of every check. |

Every auto check ends in one status:

| Status | Meaning |
| --- | --- |
| `FAIL` / `WARN` | Does not meet the policy; the severity comes from the policy file (`checks:` section). |
| `PASS` | Meets the policy. |
| `UNKNOWN` | The API key could not read the fact (role) or the API errored. Never counted as a failure; the message names the role needed. |
| `NA` | Not applicable: shared/Flex tier, a prerequisite failed already (backups off makes the PIT window moot), or the policy says the control is not required. The message says which. |
| `SKIPPED` | Severity `off` in the policy. |
| `DISCUSS` | People/process item for the workshop. |

Default severities follow one rule: `fail` when the gap can lose data or expose the cluster
(0.0.0.0/0, TLS below 1.2, fewer than 3 electable nodes, no termination protection, backups or
point-in-time restore off, auditing off), `warn` for governance and recommendations a landing
zone may legitimately decide differently (tags, alerts, autoscaling, BYOK, snapshot copies,
maintenance window, password users). Change any of them in `checks:`.

### What is checked

29 automatic checks and 17 discussion items; `mongoops waf-check checks` prints the full list.
Highlights per pillar, with the Admin API evidence:

* **Security**: no `0.0.0.0/0` and no CIDR wider than the policy floor in the access list;
  private endpoint (or peering, per `network.mode`) attached to the cluster; minimum TLS;
  no SCRAM users in scope of the cluster (Atlas cannot rotate passwords, the session's point);
  customer-managed keys; auditing enabled; server-side JavaScript off.
* **Reliability**: electable nodes per shard, regions, termination protection, Cloud Backup,
  continuous backup, restore window vs RPO, snapshot frequencies, snapshot copy, Backup
  Compliance Policy, maintenance window and protected hours, MongoDB version floor.
* **Operational efficiency**: required tags (`application`, `environment`, `contact`,
  `criticality` by default), recommended alerts present and enabled, observability integration
  (Datadog, Prometheus, ...) when the policy names one, advisors enabled on the project.
* **Performance**: compute and storage autoscaling, outstanding Performance Advisor index
  suggestions, cluster-level `defaultMaxTimeMS` when the policy asks for it.
* **Cost**: longest snapshot retention vs the policy ceiling.
* **Discuss**: org/project layout, Terraform ownership, roles and change control, support and
  training, developer access, federated auth roll-out, CSFLE/Queryable Encryption and the
  driver-only export path, CA pinning, compliance standards, RPO/RTO, DR runbook and restore
  drill, failover testing with retryable writes, schema/index review cadence, read locality
  and sharding, idle clusters, data lifecycle (TTL / Online Archive), billing by tag.

### Roles the key needs

| Endpoint | Role | If missing |
| --- | --- | --- |
| Cluster, processArgs, backup schedule, access list, peers, maintenance window, alert configs, database users, project settings | Project Read Only | (baseline) |
| `auditLog`, `integrations`, `backupCompliancePolicy` | Project Owner | `sec.audit.enabled`, `ops.integrations.observability`, `rel.backup.compliance-policy` -> `UNKNOWN` |
| `performanceAdvisor/suggestedIndexes` | Project Data Access Read Only | `perf.advisor.suggested-indexes` -> `UNKNOWN` |

A read-only key is enough for a first report; the HTML lists what it could not read.

### Output and gating

`-f table|json|html`, `-o FILE`, `--html FILE` (always in addition). The JSON has
`summary.by_status`, `summary.by_pillar`, `checks[]` (id, status, severity, evidence, remedy,
doc) and `discuss[]`. `--fail-on fail` exits 1 on any `FAIL`; `--fail-on warn` also on `WARN`;
default `never` (exit 0, findings or not, 2 on usage or API errors). `UNKNOWN` never trips
the gate.

Scope in this version is one cluster plus the project settings it inherits (access list,
audit, alerts, maintenance window). Project-level facts are fetched once per run, so scoring a
whole project later is a loop over clusters, not a redesign.

## Running it from Ansible or a CI/CD pipeline

Guidelines only; nothing in the repo assumes a particular automation tool. The properties that
make the tool easy to automate:

* **Read-only and idempotent.** It never writes to the cluster, so it can run on any schedule and
  in any environment, including production.
* **Machine-readable output.** `-f json` gives `{"summary": [...], "findings": [...]}`; every row
  has `category`, `remedy`, `collscan_count` / `plan_summary`, so a gate is a `jq` expression.
* **Exit codes.** `0` when the run succeeded (findings or not), `2` on a usage or API error. The
  tool does not fail on findings by itself; the gate decides, see below.
* **Credentials via environment.** The same variable names as the Atlas CLI and mongocli, so
  Vault, CI secrets or an `environment:` block all work; no `.env` file has to touch disk.
* **Self-contained HTML.** `--html` produces one file suitable as a pipeline artifact.

### Ansible

Typical placement: one play on a control or bastion host for the API sources (`atlas`,
`ops-manager`), delegated and `run_once`; or, for EA fleets without Ops Manager, a play across
the `mongod` hosts running `logfile` against the local log so no API key is needed at all.

```yaml
- name: regex-finder against Performance Advisor
  hosts: bastion
  vars:
    mongoops_venv: /opt/mongoops/.venv
    report_dir: "/var/lib/mongoops/reports/{{ ansible_date_time.date }}"
  tasks:
    - name: Install mongoops (pin a tag or commit)
      ansible.builtin.pip:
        name: "git+https://github.com/Guide-V/oper-runbook.git@main"   # pin a tag once released
        virtualenv: "{{ mongoops_venv }}"
        virtualenv_command: python3 -m venv

    - name: Run regex-finder                       # read-only, so never "changed"
      ansible.builtin.command: >
        {{ mongoops_venv }}/bin/mongoops regex-finder atlas
        --cluster {{ item }} --since 7d
        -f json -o {{ report_dir }}/{{ item }}.json
        --html {{ report_dir }}/{{ item }}.html
      loop: "{{ atlas_clusters }}"
      environment:                                 # from Ansible Vault, never on disk
        MONGODB_ATLAS_PUBLIC_API_KEY: "{{ vault_atlas_public_key }}"
        MONGODB_ATLAS_PRIVATE_API_KEY: "{{ vault_atlas_private_key }}"
        MONGODB_ATLAS_PROJECT_ID: "{{ atlas_project_id }}"
      changed_when: false
      no_log: true                                 # keeps keys out of the task log

    - name: Fail the play on index-defeating shapes with a Search or write-filter remedy
      ansible.builtin.command: >
        jq -e '[.summary[] | select(.remedy | IN("search","fix_filter","btree_index"))] | length == 0'
        {{ report_dir }}/{{ item }}.json
      loop: "{{ atlas_clusters }}"
      changed_when: false

    - name: Bring the dashboards back to the controller
      ansible.builtin.fetch:
        src: "{{ report_dir }}/{{ item }}.html"
        dest: "reports/"
        flat: true
      loop: "{{ atlas_clusters }}"
```

For the log-file variant replace the command with
`mongoops regex-finder logfile /var/log/mongodb/mongod.log --min-ms 100 -f json -o ...` on
`hosts: mongod`, and drop the `environment:` block. Schedule with AWX/Tower or cron; keep the
dated `report_dir` so trends are visible.

### CI/CD quality gate

Performance Advisor only knows about queries that actually ran, so the gate belongs *after*
something exercised the database, not on a pull request's unit tests. Two placements work well:

1. **Post-deploy / nightly against staging.** After the regression or load suite has run, call
   `mongoops regex-finder atlas -c <staging cluster> --since <pipeline start>` and gate on the
   result. Pass the pipeline start time as ISO-8601 so the window covers exactly this run.
2. **Inside the integration-test job.** Point the test suite at a throw-away MongoDB (container
   or atlas-local), set `db.adminCommand({profile: 0, slowms: -1})` so every operation is logged,
   run the tests, then run `mongoops regex-finder live --uri ... -n <your namespaces>` or `logfile`
   on the container log. This catches a new unanchored regex the day it is written, with no Atlas
   credentials in CI.

Gate policy that has worked in practice: **block** on `search`, `fix_filter` and `btree_index`
(a real scan with a known fix), **warn** on `collation_index`, `reversed_field` and `rewrite`,
ignore `none` and `monitor`. Expressed with `jq`:

```bash
mongoops regex-finder atlas -c "$CLUSTER" --since "$PIPELINE_START" -n "$NAMESPACES" \
  -f json -o reports/regex.json --html reports/regex.html

blocking=$(jq '[.summary[] | select(.remedy | IN("search","fix_filter","btree_index"))] | length' reports/regex.json)
warnings=$(jq '[.summary[] | select(.remedy | IN("collation_index","reversed_field","rewrite"))] | length' reports/regex.json)
echo "blocking=$blocking warnings=$warnings"
jq -r '.summary[] | "\(.remedy)\t\(.namespace)\t\(.field)\t\(.sample_pattern)\t\(.remedy_how)"' reports/regex.json
test "$blocking" -eq 0
```

Ratchet instead of a hard rule when starting on a cluster that already has findings: commit the
current shapes as a baseline and fail only on *new* ones.

```bash
# once: jq '[.summary[] | {namespace, field, command, category}]' reports/regex.json > regex-baseline.json
jq -n --slurpfile now reports/regex.json --slurpfile base regex-baseline.json \
  '[$now[0].summary[] | {namespace, field, command, category}] - $base[0] | length == 0' -e
```

Minimal GitHub Actions job (GitLab CI is the same shape: `script:` plus `artifacts: paths: [reports/]`):

```yaml
regex-gate:
  runs-on: ubuntu-latest
  needs: [integration-tests]
  env:
    MONGODB_ATLAS_PUBLIC_API_KEY: ${{ secrets.ATLAS_PUBLIC_KEY }}
    MONGODB_ATLAS_PRIVATE_API_KEY: ${{ secrets.ATLAS_PRIVATE_KEY }}
    MONGODB_ATLAS_PROJECT_ID: ${{ vars.ATLAS_PROJECT_ID }}
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: "3.12" }
    - run: pip install "git+https://github.com/Guide-V/oper-runbook.git@main"  # pin a tag once released
    - run: |
        mongoops regex-finder atlas -c staging --since "${{ github.event.head_commit.timestamp }}" \
          -f json -o reports/regex.json --html reports/regex.html
        test "$(jq '[.summary[] | select(.remedy | IN("search","fix_filter","btree_index"))] | length' reports/regex.json)" -eq 0
    - uses: actions/upload-artifact@v4
      if: always()
      with: { name: regex-dashboard, path: reports/ }
```

Practical notes:

* **Runner IPs.** If the organisation requires an API access list, the CI runners' egress IP must
  be on the key's list. Hosted runners rotate IPs; use a self-hosted runner or a fixed NAT.
* **Least privilege.** The CI key needs only `GROUP_DATA_ACCESS_READ_ONLY` (+ `GROUP_READ_ONLY`)
  on the staging project. Do not reuse a production key.
* **Scope the gate.** Always pass `-n` with the namespaces the service owns; otherwise another
  team's regex fails your pipeline.
* **Ingestion lag.** Performance Advisor trails the workload by a few minutes. Either run the gate
  as a later stage, or loop `until jq ... ; do sleep 30; done` with a cap as
  `scripts/dev/atlas_live_check.sh` does.
* **Keep the dashboard.** Upload `reports/` as an artifact on every run, including failures; the
  "What to do" section is the message to send back to the developer.
* A native `--fail-on <remedy,...>` flag would remove the `jq` step; it is listed as a follow-up
  in `spec.md` and easy to add once the team has settled on a policy.

## Development

```bash
make check              # ruff format --check, ruff check, mypy --strict, pytest
make test               # unit tests only (no network, no database)
```

### Probe: what is there right now (read-only)

```bash
make probe-atlas                                    # Performance Advisor, last 24h, summary view
make probe-atlas ATLAS_CLUSTER=Cluster0 SINCE=7d NAMESPACE=app.orders VIEW=both
make probe-atlas ARGS="-f csv --output /tmp/regex.csv"
make probe-local                                    # atlas-local via getLog
```

Knobs: `ATLAS_CLUSTER` (default `cluster-free`), `SINCE` (default `24h`, relative or ISO-8601),
`NAMESPACE` (optional `db.coll` filter), `VIEW` (`summary`, `details`, `both`), `ARGS` (anything
else `mongoops regex-finder` accepts), `REPORT_DIR` (default `reports`). Nothing is written to the
cluster; each run leaves an HTML dashboard in `reports/` (see above).

`probe-local` reads the server's in-memory log ring buffer (1024 lines). On atlas-local the
built-in mongot and health-check connections produce about two log lines per second, so the buffer
only covers the last ~8 minutes; probe right after a workload, or use `logfile` against the
container's `mongod.log` for anything older.

### End-to-end checks: one command each

```bash
make test-atlas-local                        # atlas-local: ~10 s, no Atlas account needed
make test-atlas-live ATLAS_CLUSTER=<name>    # real cluster via Performance Advisor: ~5-10 min
```

`test-atlas-local` starts (or creates) the `mongoops-regex-test` local deployment if needed, runs
`pytest -m integration` (seeds a throw-away database, forces every op to be logged as slow, checks
the `live` source), then runs `scripts/dev/seed_regex_workload.js` and prints the summary report.

`test-atlas-live` runs `scripts/dev/atlas_live_check.sh`, which:

1. creates a temporary DB user scoped to the cluster (`readWrite` on `mongoops_test` only),
2. seeds 300k documents and a regex workload with `scripts/dev/seed_regex_workload_atlas.js`
   (Atlas picks the slow threshold from the cluster's average op time, so the scans need real
   volume to register; `MONGOOPS_SEED_DOCS` changes the size),
3. polls `mongoops regex-finder atlas` until Performance Advisor has ingested the seeded regexes
   (typically 3-5 minutes, `WAIT_SECONDS` caps it, default 600),
4. runs `pytest -m atlas_live` (`tests/integration/test_atlas_live.py`) and prints the report,
5. always drops the seeded collection and deletes the temporary user, even on failure.

It needs the Atlas CLI logged in with Project Owner (to create the user), `mongosh`, and a `.env`
with `MONGODB_ATLAS_PROJECT_ID` plus an API key as described above. The cluster must be M10 or
larger (Performance Advisor is not available on Free or Flex tiers).

Individual steps are available too:

```bash
make atlas-local-up     # atlas deployments setup mongoops-regex-test --type local --port 27099
make atlas-local-seed   # runs scripts/dev/seed_regex_workload.js, then `mongoops regex-finder live`
make test-integration   # pytest -m integration against the local deployment
make atlas-local-down   # delete the deployment
```

`tests/fixtures/atlas_local_slow_queries.jsonl` contains real slow-query lines captured this way
(MongoDB 8.0), so the unit tests exercise genuine server output without needing a database. The
Atlas and Ops Manager API clients are additionally tested against an in-memory
`httpx.MockTransport` using response shapes copied from a real project.

## Layout

```
src/mongoops/
  cli.py                     mongoops entry point; mounts one sub-app per script
  common/
    mongolog.py              mongod slow-query line -> SlowQuery (JSON 4.4+ and legacy 4.2)
    perf_advisor.py          slowQueryLogs fetch + pagination shared by Atlas and Ops Manager
    atlas_api.py             Atlas Admin API v2 client (digest or service account)
    ops_manager_api.py       Ops Manager / Cloud Manager API client (digest)
    timeutil.py              --since / --duration parsing
    html_theme.py            CSS + table filter/sort script shared by every HTML report
  waf_check/
    model.py                 Pillar / Kind / Severity / Status, CheckSpec, Outcome -> CheckResult
    catalog.py               check ids mapped to the operational-readiness checklist (+ discuss items)
    policy.py                landing-zone policy: defaults, YAML load/validate, commented writer
    facts.py                 Atlas Admin API collectors; 401/403 -> Fact(error) not failure
    checks.py                pure evaluators, one per auto check
    report.py                table / json rendering, Scope, sorting and counts
    html_report.py           self-contained HTML scorecard
    cli.py                   typer sub-commands: atlas, init, checks
  regex_finder/
    detector.py              pure regex detection + index-friendliness classification
    analyze.py               SlowQuery x RegexUsage -> Finding, filters
    remedy.py                pure rule table: finding -> remedy + instruction
    summary.py               per-shape aggregation, severity order, advice text
    report.py                table / csv / json rendering, dispatch to html
    html_report.py           self-contained HTML dashboard
    sources.py               I/O adapters: atlas, ops-manager, logfile, live
    cli.py                   typer sub-commands
tests/                       unit tests (default) and tests/integration (opt-in, -m integration)
examples/landing-zone.yaml   the policy `waf-check init` writes (a test keeps it in sync)
scripts/dev/                 seed workloads (atlas-local and real Atlas)
spec.md                      decision log
```
