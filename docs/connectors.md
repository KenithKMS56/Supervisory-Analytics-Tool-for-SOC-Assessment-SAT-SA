# SAT-SA Source Connectors: Splunk ES, ServiceNow SIR, TheHive 5, Cortex XSIAM

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

A CSE does not have to re-shape its data into SAT-SA's canonical CSV layout. For four products,
a mapping in `config/mappings/` translates the product's own export:

```bash
satsa ingest --data-dir <export dir> --source splunk     --entity CSE-07
satsa ingest --data-dir <export dir> --source servicenow --entity CSE-07
satsa ingest --data-dir <export dir> --source thehive    --entity CSE-07
satsa ingest --data-dir <export dir> --source xsiam      --entity CSE-07
satsa ingest --data-dir <export dir> --mapping my_mapping.yaml --entity CSE-07   # any other product
```

`--entity` is required: a product export does not say which CSE it belongs to. Several exports
can be ingested for the same entity (a SIEM export and a ticketing export); what the entity has
submitted accumulates, and so does the set of rules that can be assessed.

**Recognised by its columns.** A mapping can list, per table, the columns that identify its
export (`headers:`). When every file of a submission is one product's export and at least one
file carries those columns, `satsa ingest` without `--source` and the `/upload` page use that
mapping, whatever the files are called (`detect_source_mapping`). This is an exact match on
column names the mapping declares; a canonical submission, or one mixing a product export with
canonical files, is read in the canonical layout. The XSIAM mapping is the first to use it.

**What has and has not been verified.** The sample exports in `tests/fixtures/connectors/` are
hand-built (`build_fixtures.py`) to the field names of each product's export or API schema as
documented. They are **not** captures from live systems, and the mappings have **not** been run
against a real Splunk, ServiceNow or TheHive instance. Every number on this page was measured
by running those samples through ingestion and assessment (`tests/test_connectors.py`). A real
export may use different columns (custom fields, renamed statuses, another time zone); the
mapping files are the place to adjust, and the ingest report shows at once what did not map.

---

## 1. What each export supplies

Counts are rows with a usable value, out of the rows ingested from the sample export.

### 1.1 Splunk Enterprise Security (`config/mappings/cse_splunk.yaml`)

Files: `notable_events*.csv` (notable events) and `incident_review*.csv` (review history,
`| inputlookup incident_review_lookup`).

| Canonical field | Source column | Sample (209 notables) | Note |
|---|---|---|---|
| `alert.alert_id` | `event_id` | 209 / 209 | |
| `alert.rule_id` | `rule_name` | 209 / 209 | |
| `alert.category` | `security_domain` | 209 / 209 | ES domains (access, endpoint, network, threat), not SAT-SA's category list |
| `alert.severity_orig` | `severity` | 209 / 209 | severity set by the correlation search |
| `alert.severity_final` | `urgency` | 209 / 209 | severity combined with asset priority |
| `alert.asset_id` | `dest` | 209 / 209 | |
| `alert.created_at` | `_time` | 209 / 209 | ISO 8601 with offset, converted to UTC |
| `alert.closed_at` | `review_time` when `status_group` is `Closed` | 175 / 209 | the other 34 are still open |
| `alert.closed_by` | `owner` when closed | 175 / 209 | pseudonymised |
| `alert.closed_by_type` | `owner` against a list of service accounts | 209 / 209 | list is in the mapping; extend per site |
| `alert.disposition` | `disposition_label` | 175 / 209 | |
| `alert.status` | `status_label` | 209 / 209 | |
| `alert.acknowledged_at`, `alert.first_touch_at` | none | 0 / 209 | a flat notable export has only the latest review time |
| `alert.playbook_id` | none | 0 / 209 | |
| `workflow_event.*` | `incident_review`: `rule_id`, `time`, `user`, `status`, `comment` length | 314 rows | `from_status` is not in the lookup (0 / 314) |
| `closure.*` | `incident_review` rows with status Resolved/Closed | 175 rows | comment is redacted, hashed and dropped |

Not in these exports: cases, case-alert links, escalations, asset inventory, log-source volumes,
detection-rule list, SLA policy, declared KPIs, external reports, remediation tickets.
Source columns left unused: `src`, `user`, `reviewer`, `comment` and the numeric `status` /
`disposition` in the notable export; `owner`, `rule_name`, `urgency` in the review history.

### 1.2 ServiceNow Security Incident Response (`config/mappings/cse_servicenow.yaml`)

Files: `sn_si_incident*.csv` (security incident list, with `sys_id`) and `sys_audit*.csv`
(field-change audit rows).

| Canonical field | Source column | Sample (14 incidents) | Note |
|---|---|---|---|
| `case.case_id` | `number` | 14 / 14 | |
| `case.severity` | `priority` | 14 / 14 | "1 - Critical" ... "4 - Low" |
| `case.status` | `state` | 14 / 14 | |
| `case.owner` | `assigned_to` | 14 / 14 | a person's name; pseudonymised |
| `case.opened_at` | `opened_at` | 14 / 14 | local time at `utc_offset` (+05:30 in the mapping), converted to UTC |
| `case.closed_at` | `closed_at` | 9 / 14 | the other 5 are still open |
| `workflow_event.*` | `sys_audit` rows where `tablename` = `sn_si_incident` and `fieldname` = `state` | 50 rows | `documentkey` (a `sys_id`) is translated to the incident number |
| `workflow_event.note_len` | none | 0 / 50 | work notes live in `sys_journal_field`, not exported here |

Not in these exports: alerts (so every alert-based rule), case-alert links, escalations,
external reports (SIR has no field for CERT-In / NCIIPC notification), and the supporting tables.
Source columns left unused: `short_description`, `close_notes`, `close_code`, `cmdb_ci`,
`category`, `assignment_group`, `sys_created_on`; `reason` in the audit export.

### 1.3 TheHive 5 (`config/mappings/cse_thehive.yaml`)

Files: `thehive_alerts*.json` (`listAlert`) and `thehive_cases*.json` (`listCase`).

| Canonical field | Source field | Sample (94 alerts, 8 cases) | Note |
|---|---|---|---|
| `alert.alert_id` | `_id` | 94 / 94 | |
| `alert.rule_id` | `title` | 94 / 94 | **approximate**: TheHive has no rule identifier; a stable title depends on the feeder |
| `alert.category` | `type` | 94 / 94 | coarse (`siem`, `ids`, `misp`) |
| `alert.severity_orig`, `alert.severity_final` | `severity` (1-4) | 94 / 94 | one value for both: no re-grading is recorded |
| `alert.created_at` | `date` | 94 / 94 | epoch milliseconds |
| `alert.acknowledged_at`, `alert.first_touch_at` | `inProgressDate` | 49 / 94 | |
| `alert.closed_at` | `closedDate`, else `importedDate` | 83 / 94 | |
| `alert.closed_by` | `assignee` | 83 / 94 | a login (e-mail address); pseudonymised |
| `alert.status` | `stage` | 94 / 94 | |
| `alert.asset_id` | none | 0 / 94 | observables are separate objects, not in the alert export |
| `alert.disposition` | none | 0 / 94 | the verdict is recorded on the case, not the alert |
| `alert.playbook_id` | none | 0 / 94 | |
| `case_alert_link.*` | `caseId`, `_id` | 6 rows | alerts imported into a case |
| `case.*` | `_id`, `severity`, `stage`, `assignee`, `startDate`, `endDate` | 8 / 8 (`closed_at` 4 / 8) | |

Not in these exports: workflow events (TheHive's audit trail is a separate API), closures,
escalations, external reports and the supporting tables.

### 1.4 Cortex XSIAM (`config/mappings/cse_cortex_xsiam.yaml`)

File: the case list exported from the Cases page (CSV, 57 columns), under any name: it is
recognised by its `Case ID`, `Creation Time`, `Resolution Reason` and `Case Domain` columns.
The export is Windows-1252 text with dates such as `Oct 1st 2026 22:31:34`; both are read as
they are.

**Built from one real export holding one case.** That export also held 5,476 rows of empty cells
and 1,266 rows with only a pasted `Investigation_time` value and no case id: these are reported
as rejected rows (`rows_rejected`, with their row numbers), not stored. The tests use a synthetic
export with the same columns, encoding and quirks (`tests/test_xsiam_mapping.py`); the real one
is not committed, since it names people and a customer. Values the mapping names but that export
did not contain (statuses `New`, `Under Investigation`) are marked "not seen" in the file.

| Canonical field | Source column | Note |
|---|---|---|
| `case.case_id` | `Case ID` | stored as text |
| `case.severity` | `Severity` | Low / Medium / High / Critical |
| `case.status` | `Status` | Resolved is `closed`; New and Under Investigation are `open` |
| `case.owner` | `Assignee` | pseudonymised |
| `case.opened_at` | `Creation Time` | local time at `utc_offset` (+05:30 assumed: the export does not record its zone), converted to UTC |
| `case.closed_at` | `Resolved Timestamp` | |

Not mapped, on purpose: `Resolution Reason` and `Resolution Comment` (SAT-SA's closure table
belongs to alerts, and EG02/EG04 join it to alert ids: closures keyed by case id would never be
read, yet would mark those rules as assessed); `Total Issues` and the per-severity issue counts
(counts, not alerts: alerts come from the XSIAM Issues export, which this mapping does not
cover); `Assignee Email`, `Users`, `Case Description`, `Indicator IDs` (personal or free-text data
no rule reads). The ingest report lists every unused column.

---

## 2. Which rules each source can support

A rule is **assessed** when every table it reads was submitted and the alert columns it rests
on hold values. It is **not assessed** when a table was never submitted: the rule is skipped,
and the DQ view says so (`rule_not_assessed`); this is neither a finding nor a clean result.
It **cannot fire** when it runs but an alert column it needs is empty for every alert
(`rule_input_missing`): no finding from it is not evidence that the control works.

Measured on the sample exports, one entity each:

| Source | Assessed | Cannot fire (empty input) | Not assessed (table never submitted) |
|---|---|---|---|
| Splunk ES | 8: EG01, EG02, EG04, EG07, EG11, NS02, NS03, NS08 | none | 12: EG03, EG08 (escalation); EG05 (remediation); EG06 (sla_policy); EG09, EG12 (case); EG10 (declared_kpi); NS01, NS06 (asset, log_source_daily); NS04 (case_alert_link); NS05 (detection_rule); NS07 (case, external_report) |
| ServiceNow SIR | 2: EG09, EG12 | none | 18: the 15 alert-based rules (no alert table); EG08 (escalation); NS01 (asset, log_source_daily); NS07 (external_report) |
| TheHive 5 | 5: EG07, EG09, NS02, NS03, NS08 | 2: EG11, NS04 (`alert.disposition` empty) | 13: EG01, EG12 (workflow_event); EG02 (workflow_event, closure); EG04 (closure); EG03, EG08 (escalation); EG05 (remediation); EG06 (sla_policy); EG10 (declared_kpi); NS01, NS06 (asset, log_source_daily); NS05 (detection_rule); NS07 (external_report) |
| Cortex XSIAM case list | 1: EG09 | none | 19: the 15 alert-based rules (no alert table); EG08 (escalation); EG12 (workflow_event); NS01 (asset, log_source_daily); NS07 (external_report) |
| Splunk ES + ServiceNow SIR, same entity | 10: the Splunk eight plus EG09, EG12 | none | 10 |

No single product export supports all 20 rules. The tables a product does not hold (asset
inventory, log-source volumes, SLA policy, declared KPIs, external reports, remediation
tickets, detection-rule list) have to be submitted alongside it in the canonical CSV layout
(`docs/data_requirements.md`); a header-only file declares a table as submitted and empty.

Findings on the sample exports (each sample carries the patterns named in `build_fixtures.py`):

| Source | Findings | What they rest on |
|---|---|---|
| Splunk ES | EG02, EG07 | 36 notables closed by one analyst within one hour, with no investigation step and an 18-character comment (36 of 164 human closures) |
| ServiceNow SIR | EG09, EG12 | 4 incidents open more than 14 days as of the export's last timestamp; 3 critical incidents closed with no Contain state in their audit history |
| TheHive 5 | EG07, EG09 | 34 alerts closed by one analyst within one hour; 4 cases open more than 14 days |

---

## 3. What ingestion reports

Every `satsa ingest` (canonical layout or product export) now prints, and returns in its
result, what the submission does not contain:

```
[+] Ingestion completed successfully:
  * Source mapping: thehive5
    - alert: 94 rows; no value for: asset_id, playbook_id, disposition
    - case: 8 rows; every column filled
  * Rule coverage for CSE-07:
    - Not assessed (table never submitted): EG01 (no workflow_event); EG03 (no escalation); ...
    - Cannot fire (input column empty): EG11 (alert.disposition empty); NS04 (alert.disposition empty)
```

| DQ check | When | Severity |
|---|---|---|
| `rule_not_assessed` | a table the rule reads (the alert table included) was never submitted by the entity | warning |
| `rule_dependency_empty` | the table was submitted but holds no rows for the entity | warning |
| `rule_input_missing` | an alert column the rule rests on has no usable value in any of the entity's alerts | warning |
| `file_not_mapped` | a file in the export directory is not described by the mapping; it is not ingested and not guessed at | warning |

---

## 4. Privacy

- Analyst identifiers are pseudonymised (HMAC-SHA256 with a local salt): alert closers
  (`ANALYST_…`), workflow actors (`ACTOR_…`) and case owners (`OWNER_…`).
- Closure comments are redacted, hashed and dropped; only the comment hash, its length and hashed
  word shingles are kept. Nothing readable from the comment is stored.
- Only canonical columns are stored. A source column the model does not know (a description, a
  source IP, close notes) is not written to the Parquet store.

`tests/test_connectors.py::test_no_personal_identifier_from_an_export_is_stored` checks, for
each sample export, that none of the analyst names, e-mail addresses, IP prefixes or comment
texts it contains appears in any Parquet file or in the findings, evidence, review-queue,
DQ or audit tables.

---

## 5. Writing a mapping for another product

```yaml
source: my_siem
timestamp_format: "%Y-%m-%d %H:%M:%S"     # or epoch_ms, epoch_s, iso
utc_offset: "+05:30"                       # zone of timestamps that carry no offset (default UTC)
sequential_ids: false                      # ids are not a running counter: skip the id-gap check
tables:
  - table: alert                           # canonical table this file feeds
    files: ["alerts_export*"]              # file-name patterns (without extension)
    headers: ["Alert Id", "Detected On"]   # optional: columns that identify the export by content
    required: [alert_id, created_at]       # rows lacking these are dropped
    where: {record_type: [alert]}          # optional row filter on source columns
    columns:
      alert_id: id                                           # plain column
      asset_id: observable.host                              # nested JSON field
      closed_at: {column: [resolved_at, ignored_at]}         # first one that has a value
      closed_by: {column: owner, when: {state: [closed]}}    # only under a condition
      closed_by_type: {column: owner, values: owner_type, default: human}
      note_len: {column: comment, transform: length}
      ts: {column: changed, format: epoch_s}                 # per-column timestamp format
      ref_id: {column: key, lookup: {files: "cases*", key: sys_id, value: number}}
      ref_type: {const: alert}
value_mappings:
  severity: {"P1": critical}               # applied to severity*, status, disposition by name
  owner_type: {"svc-soar": automation}     # any other map is used through `values:`
```

A mapping with no `tables:` section, an undefined value map, a named time zone (use
`utc_offset`) or an incomplete lookup is rejected when it is loaded, before any row is read.
Values not covered by `value_mappings` fall back to `config/taxonomy.yaml`; what that does not
recognise becomes `unmapped` and shows up in the field report.

**Not covered yet:** the `/upload` page translates a product export only when its mapping
lists `headers:` (so far XSIAM); other product exports go through the CLI. A submission mixing a
product export with canonical files is read in the canonical layout. The REST ticketing mapping
(`cse_api_ticketing.yaml`) is a single-record mapping for `SourceAdapter.read_api` and is not a
pipeline mapping.
