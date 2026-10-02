# SAT-SA Data Requirements & Ingestion Schema

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document specifies the canonical data structures, mandatory and optional attributes of a periodic submission, and per-rule data dependencies required by **SAT-SA**.

---

## 0. Ingestion Sources: CSV, JSON, SQLite Exports, and Local APIs

`satsa.ingest.adapters.SourceAdapter` supports four source shapes, matching PS requirement #2's
list (CSV/JSON/DB exports and APIs):

- `read_csv(path)` / `read_json(path)`: file-based batch exports (used by the `/upload` drag-and-drop
  wizard and `satsa ingest`).
- `read_sqlite(path, table_name)`: a table from a SQLite database export.
- `read_api(endpoint_config)`: a JSON REST API response. This is the API path: it pulls from a
  **local** REST endpoint only. `endpoint_config["url"]` is validated against an allow-list of
  loopback hostnames (`127.0.0.1`, `localhost`, `::1`) and the call is refused with `ValueError`
  before any socket opens if it resolves to anything else -- this is what keeps the adapter
  consistent with SAT-SA's offline design (`tests/test_offline.py`). In a real deployment,
  `url` would point at an entity's own on-prem/local API reachable within the air-gapped network
  boundary (e.g. a self-hosted ticketing system's REST interface on the entity's internal LAN), never
  at the public internet. For tests and offline demos, `endpoint_config["fixture_path"]` reads a
  local JSON file that simulates the API's response body instead, exercising the identical parsing
  path with zero network I/O. See `config/mappings/cse_api_ticketing.yaml` for a worked example
  mapping a REST-exposed ticketing system's fields to the canonical `case_record` schema.

---

### Product exports (Splunk ES, ServiceNow SIR, TheHive 5)

`satsa ingest --source splunk|servicenow|thehive --entity <id>` translates a product's own
export through a mapping in `config/mappings/` (`SourceMapping`, used by `IngestionPipeline`).
Which canonical fields each export supplies, which it cannot, and which rules that leaves
assessable is measured on sample exports in `docs/connectors.md`.

---

## 1. Canonical Schema Specifications

SAT-SA standardizes multi-source periodic submissions into 8 canonical relational entities:

**Timestamps** are ISO 8601 text in a CSV or JSON submission (`2026-04-02T10:00:00`, a space in
place of the `T`, optional fractional seconds) and are held in UTC. A timestamp that carries an
offset (`Z`, `+05:30`, `+0530`, `+05`) is converted to UTC with it: `2026-04-02T10:00:00+05:30`
is stored as 04:30 UTC. One without an offset is taken to be UTC already. Text that cannot be read
as a timestamp is stored as empty. Product exports through a mapping are converted by the
mapping's `utc_offset` (`docs/connectors.md`).

### 1.1 `Entity` (Master Profile)
| Field Name | Type | Constraint | Description |
|---|---|---|---|
| `entity_id` | String | PK, Mandatory | Unique identifier (e.g., `CSE-01`, `CSE-02`). |
| `name` | String | Mandatory | Full organizational name. |
| `sector` | String | Mandatory | Critical sector (`power`, `banking`, `telecom`, `transport`, `oil_and_gas`). |
| `size_band` | String | Mandatory | Relative operational scale (`small`, `medium`, `large`). |
| `soc_model` | String | Optional | Operating model (`inhouse`, `hybrid`, `mssp`). |
| `soc_provider` | String | Optional | The SOC operator: `internal` for an in-house SOC, otherwise the third-party provider's name. Used by the systemic detector. |
| `timezone` | String | Optional | Local operational timezone (default `UTC`). |
| `declared_shift_hours` | String | Optional | Operational shift windows (e.g., `09:00-18:00` or `24x7`). |

### 1.2 `Alert` (Submitted Alert Records)
| Field Name | Type | Constraint | Description |
|---|---|---|---|
| `entity_id` | String | Mandatory | Foreign key to `Entity`. |
| `alert_id` | String | PK, Mandatory | Unique alert record ID. |
| `rule_id` | String | Mandatory | Source detection rule or signature identifier. |
| `category` | String | Mandatory | Threat categorization (normalized to MITRE or standard taxonomy). |
| `severity_orig` | String | Optional | Ingested severity label. |
| `severity_final` | String | Mandatory | Standardized severity (`low`, `medium`, `high`, `critical`). |
| `asset_id` | String | Optional | Target device or asset affected. |
| `created_at` | Timestamp | Mandatory | Alert generation timestamp (UTC). |
| `acknowledged_at` | Timestamp | Optional | First examiner acknowledgment timestamp. |
| `first_touch_at` | Timestamp | Optional | Timestamp of initial investigation step. |
| `closed_at` | Timestamp | Optional | Alert closure timestamp. |
| `closed_by` | String | Optional | HMAC-pseudonymised analyst ID. |
| `closed_by_type` | String | Mandatory | Actor type (`human` or `soar`). |
| `playbook_id` | String | Optional | Identifier of automated response playbook. |
| `disposition` | String | Mandatory | Resolution outcome (`true_positive`, `false_positive`, `benign`, `unknown`). |
| `status` | String | Mandatory | Operational state (`open`, `in_progress`, `closed`). |

### 1.3 `Case` (ITSM / Case Management)
| Field Name | Type | Constraint | Description |
|---|---|---|---|
| `entity_id` | String | Mandatory | Foreign key to `Entity`. |
| `case_id` | String | PK, Mandatory | Incident or investigation case number. |
| `severity` | String | Mandatory | Case severity. |
| `status` | String | Mandatory | Lifecycle state (`open`, `in_progress`, `resolved`, `closed`). |
| `owner` | String | Optional | Lead assigned analyst (pseudonymised). |
| `opened_at` | Timestamp | Mandatory | Case creation timestamp. |
| `closed_at` | Timestamp | Optional | Case resolution timestamp. |

### 1.4 `WorkflowEvent` (Lifecycle Audit Trail)
| Field Name | Type | Constraint | Description |
|---|---|---|---|
| `entity_id` | String | Mandatory | Foreign key to `Entity`. |
| `ref_type` | String | Mandatory | Target record type (`alert` or `case`). |
| `ref_id` | String | Mandatory | Target record identifier. |
| `ts` | Timestamp | Mandatory | Action timestamp. |
| `actor` | String | Mandatory | Pseudonymised analyst handle or system daemon. |
| `action` | String | Mandatory | Lifecycle transition (`triage`, `investigate`, `escalate`, `contain`, `close`). |
| `from_status` | String | Optional | Prior state. |
| `to_status` | String | Optional | Resulting state. |
| `note_len` | Integer | Optional | Character count of investigator notes. |

### 1.5 Supporting Tables
(Column names as `satsa.models.canonical` defines them; corrected in the quality pass: writing a test-data generator from this page showed that several names and value lists here differed from the code.)
- `asset`: Inventory master list (`asset_id`, `asset_type`, `criticality` 1–4, `monitored_flag`, `owner_unit`).
- `escalation`: Escalation events (`esc_id`, `ref_id`, `escalated_at`, `from_role`, `to_role`, `acknowledged_at`, `outcome`).
- `closure`: Detailed resolution records (`ref_id` = the alert ID, `reason_code`, `disposition`, `comment_norm_hash`, `comment_len` (EG02 reads it), `comment_shingles`).
- `log_source_daily`: Daily aggregate event volumes (`asset_id`, `source_type`, `date`, `event_count`).
- `declared_kpi`: Entity self-attestations (`period`, `metric` e.g. `MTTR`, `severity`, `value`; EG10 reads `metric = 'MTTR'` in minutes).
- `external_report`: Regulatory filings (`incident_id` = the case ID, `reported_to`, `reported_at`).
- `detection_rule`: The entity's detection catalogue (`rule_id`, `category`, `mitre_tactic`, `mitre_technique`, `enabled`, `last_fired`).
- `remediation`: Tuning and fix tickets (`ticket_id`, `linked_asset_id`, `linked_rule_id`, `type`, `created_at`, `closed_at`); EG05 matches them on (asset, rule).
- `sla_policy`: Per-severity targets (`severity`, `ack_minutes`, `resolve_minutes`); EG06 reads `resolve_minutes`.

---

## 2. Per-Rule Data Dependencies

The table below lists the tables each rule actually reads. A rule that treats absence as the
signal cannot, from the data alone, tell "this SOC never did this" from "this table was not
submitted": with no `escalation` table, EG03 would read every Critical true positive as unescalated.
SAT-SA resolves this with a **submission manifest**, recorded automatically at ingest: the tables
each entity has ever submitted (a file or payload section was present, even with zero rows).

When an entity has no rows in a table marked **bold** below, each assessment run does one of three
things and says which on the Data Quality view (`/dq`):

| The entity's manifest | What happens | DQ entry |
|---|---|---|
| Does **not** include the table | The dependent rules are **not assessed** for that entity: no finding, and no clean result either. | `rule_not_assessed` (one per rule, naming the missing table) |
| Includes the table, but it has no rows for the entity | The rules **run**: the entity submitted an empty table, so absence is a real signal. | `rule_dependency_empty` ("submitted ... but holds no records") |
| No manifest at all (data stored before manifests existed, or written directly) | The rules **run**, as before. | `rule_dependency_empty` ("no record of what it submitted": the finding may be an artifact) |

**To state that a table is complete and empty, submit it with headers and no rows.** An entity
that leaves a table out is not flagged by the rules that need it, but every such rule is listed
as not assessed, so withholding a table is visible rather than rewarded. The JSON endpoint
(`POST /api/v1/submissions`) carries only alerts, cases, assets and closures, so rules needing other
tables are not assessed for entities submitted that way.

| Rule ID | Rule Name | Tables read | Flagged on `/dq` when the entity has no rows in |
|---|---|---|---|
| **EG01** | Fast Closures Without Investigation | `alert`, `workflow_event` | **`workflow_event`** |
| **EG02** | Acknowledged Without Investigation | `alert`, `workflow_event`, `closure` | **`workflow_event`**, **`closure`** |
| **EG03** | Missing Escalations | `alert`, `escalation` | **`escalation`** |
| **EG04** | Template Closure Comments | `alert`, `closure` | **`closure`** |
| **EG05** | Repeat Alerts No Root Cause | `alert`, `remediation` | **`remediation`** |
| **EG06** | Metric Gaming & SLA Distortions | `alert`, `sla_policy` | **`sla_policy`** |
| **EG07** | Analyst Implausibility | `alert` | — |
| **EG08** | Escalation Without Follow-Through | `escalation` | **`escalation`** |
| **EG09** | Backlog & Aging Accumulation | `case` | **`case`** |
| **EG10** | KPI Reconciliation Gap | `alert`, `declared_kpi` | **`declared_kpi`** |
| **EG11** | Disposition Extremes | `alert` | — |
| **EG12** | Workflow Non-Conformance | `case`, `workflow_event` | **`case`**, **`workflow_event`** |
| **NS01** | Silent Critical Assets | `asset`, `log_source_daily` | **`asset`**, **`log_source_daily`** |
| **NS02** | Missing Alert Categories | `alert` | — |
| **NS03** | Unexpected Low/Flat Activity | `alert` | — |
| **NS04** | Missing Records | `alert`, `case_alert_link` | **`case_alert_link`** |
| **NS05** | Inactive Rule Coverage | `detection_rule`, `alert` | **`detection_rule`** |
| **NS06** | Inventory vs Telemetry | `asset`, `alert`, `log_source_daily` | **`asset`**, **`log_source_daily`** |
| **NS07** | Absent External Reporting | `case`, `external_report` | **`case`**, **`external_report`** |
| **NS08** | Submission Completeness | `alert` | — |

Ingest also reports, on the same view: missing required fields, close-before-create timestamps,
duplicate IDs, alert-ID sequence gaps, high null rates, and orphaned references (a closure,
workflow event, escalation or case link whose alert is not in the submission, a case link whose
case is missing, an alert whose asset is not in the inventory). Orphaned child records both
distort the rules above and can indicate that alerts were withheld. A table that fails to store
(`table_write_failed`) or a file that cannot be read (`file_unreadable`) is reported as an error
and left out of the manifest, so its rules are not assessed on missing data; after a failed store
no assessment is run on that upload.
